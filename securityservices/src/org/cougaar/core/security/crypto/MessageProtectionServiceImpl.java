/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * Created on September 12, 2001, 10:55 AM
 */
 
package org.cougaar.core.security.crypto;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.lang.ClassNotFoundException;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.text.MessageFormat;
import java.text.ParseException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.util.*; 

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.SendQueue;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.AttributedMessage;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.AttributeConstants;
import org.cougaar.core.mts.ProtectedInputStream;
import org.cougaar.core.mts.ProtectedOutputStream;
import org.cougaar.core.mts.SimpleMessageAttributes;
import org.cougaar.core.node.NodeMessage;
import org.cougaar.core.service.MessageProtectionService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;

// Cougaar security services
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.MessageFailureEvent;
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.policy.CryptoPolicy;
import org.cougaar.core.security.ssl.KeyRingSSLServerFactory;

/** Cryptographic Service used to cryptographically protect incoming
 * and outgoing messages.
 * This service should be called by the transport service for
 * all Cougaar messages.
 */

public class MessageProtectionServiceImpl
  implements MessageProtectionService
{
  private ServiceBroker serviceBroker;

  private KeyRingService keyRing;
  private EncryptionService encryptService;
  private SecurityPropertiesService secprop;
  private CryptoPolicyService cps = null;

  private LoggingService log;
  private boolean isInitialized = false;
  // event publisher to publish message failure
  private EventPublisher eventPublisher = null;
  private MessageFormat exceptionFormat = new MessageFormat("{0} -");

  public static final String NEW_CERT = 
    "org.cougaar.core.security.crypto.newcert";

  public MessageProtectionServiceImpl(ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    // Retrieve security properties service
    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this, SecurityPropertiesService.class, null);

    if (log.isDebugEnabled()) {
      log.debug("Initializing MessageProtectionServiceImpl");
    }
    
    // Retrieve KeyRing service
    this.keyRing = (KeyRingService)
      serviceBroker.getService(this, KeyRingService.class, null);
    if (this.keyRing == null) {
      log.error("Unable to get KeyRing service");
      throw new RuntimeException("MessageProtectionService. No KeyRing service");
    }

    // Retrieve Encryption service
    this.encryptService = (EncryptionService)
      serviceBroker.getService(this, EncryptionService.class, null);
    if (encryptService == null) {
      log.warn("Unable to get Encryption service");
      throw new RuntimeException("MessageProtectionService. No encryption service");
    }
  }

  // method used to initialize event publisher
  public synchronized void addPublisher(EventPublisher publisher) {
    if(eventPublisher == null) {
      eventPublisher = publisher;
    }
  }
  
  private synchronized void setPolicyService() {
    // Retrieve policy service
    cps = (CryptoPolicyService)
      serviceBroker.getService(this, CryptoPolicyService.class, null);
    if (cps == null) {
      log.error("Unable to get crypto policy service");
      throw new
	      RuntimeException("MessageProtectionService. No crypto policy service");
    }
    if (log.isDebugEnabled()) {
      log.debug("Done initializing MessageProtectionServiceImpl");
    }
    isInitialized = true;
  }

  private AttributedMessage  getCertificateMessage(MessageAddress source, 
                                                   MessageAddress destination) {
    // force refresh of destination certificate
    String destAddr = destination.toAddress();
    keyRing.findCert(destAddr, keyRing.LOOKUP_FORCE_LDAP_REFRESH);
    try {
      //X509Certificate certificate = keyRing.findFirstAvailableCert(destAddr);
      Hashtable certTable = keyRing.findCertPairFromNS(source.toAddress(), destAddr);
      X509Certificate certificate = (X509Certificate)certTable.get(destAddr);
      if (certificate == null) {
	throw new CertificateException("No target " + destAddr + " cert available.");
      }
      // NOTE: The constructor argument use to be a FakeRequestMessage for cougaar 9.x.
      //       Cougaar 10.x removed the FakeRequestMessage class.
      //       The source and destination arguments where also swapped (it was incorrect
      //       for the FakeRequestMessage constructor).
      AttributedMessage msg = 
        new AttributedMessage(new CertificateRequestMessage(source, destination));
      msg.setAttribute(NEW_CERT, certificate);
      msg.setContentsId(certificate.hashCode());
      return msg;
    } catch (CertificateException e) {
      log.error("Couldn't find certificate for " + destAddr +
                ", can't respond with a valid certificate.");
      return null;
    } // end of try-catch
    
  }

  /**
   * Sign and/or encrypt the header of an outgoing message.
   *
   * When a message is sent out:
   * 1) The aspect calls protectHeader().
   * 2) The data protection service encrypts/signs the header.
   *    It uses the information provided in the source and destination
   *    to decide how to encrypt and/or sign.
   * 3) The encrypted header is returned.
   * 4) The aspect calls getOuputStream.
   *    - The source and destination should be the same as what was found
   *      in the call to protectHeader().
   * 5) The service returns an output stream where the MTS will serialize
   *    the clear-text message.
   * 6) The service encrypts the message and write the encrypte/signed
   *    message to the output stream.
   * 7) The encrypted message is actually sent over the network.
   *
   * @param rawData     The unencrypted header
   * @param source      The source of the message
   * @param destination The destination of the message
   * @return the protected header (sign and/or encrypted)
   */
  public byte[] protectHeader(byte[] rawData,
			      MessageAddress source,
			      MessageAddress target)
    throws GeneralSecurityException, IOException
  {
//      return protectHeader(rawData, null, null, source, target, null);
     return rawData;
  }

  /**
   * Sign and/or encrypt the header of an outgoing message.
   *
   * When a message is sent out:
   * 1) The aspect calls protectHeader().
   * 2) The data protection service encrypts/signs the header.
   *    It uses the information provided in the source and destination
   *    to decide how to encrypt and/or sign.
   * 3) The encrypted header is returned.
   * 4) The aspect calls getOuputStream.
   *    - The source and destination should be the same as what was found
   *      in the call to protectHeader().
   * 5) The service returns an output stream where the MTS will serialize
   *    the clear-text message.
   * 6) The service encrypts the message and write the encrypte/signed
   *    message to the output stream.
   * 7) The encrypted message is actually sent over the network.
   *
   * @param rawData     The unencrypted header
   * @param source      The source of the message
   * @param destination The destination of the message
   * @return the protected header (sign and/or encrypted)
   */
  public byte[] protectHeader(byte[] rawData,
			      MessageAddress sourceAgent,
			      MessageAddress targetAgent,
                              MessageAddress sourceNode,
                              MessageAddress targetNode,
                              MessageAttributes attrs)
    throws GeneralSecurityException, IOException
  {
    if (isEncrypted(attrs)) {
      return rawData;
    }

    String sourceName = sourceNode.toAddress();
    String targetName = targetNode.toAddress();

    // SR - 10/21/2002. UGLY & TEMPORARY FIX
    // The advance message clock uses an unsupported address type.
    // Since this is demo-ware, we are not encrypting those messages.
    if (targetName.endsWith("(MTS)")) {
      targetName = targetName.substring(0, targetName.length() - 5);
      targetNode = MessageAddress.getMessageAddress(targetName);
      log.info("Incoming postmaster message. Protecting with node key");
    }

    if (!isInitialized) {
      setPolicyService();
    }
    
    SecureMethodParam policy = cps.getSendPolicy(sourceName, targetName);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    oos.writeObject(policy);

    if (policy == null) {
      if (log.isWarnEnabled()) {
        log.warn("protectHeader: " + sourceName +
                 " -> " + targetName + 
                 " for agents " + sourceAgent + " -> " + targetAgent +
                 " (No policy). No protection.");
      }

      GeneralSecurityException gse = 
        new GeneralSecurityException("Could not find message policy between " +
                                     sourceName +
                                     " and " + targetName);
      publishMessageFailure(sourceName, targetName,
                            MessageFailureEvent.INVALID_POLICY, 
                            gse.toString());

      IOException ioex = new IOException("Unable to protect header:" +
					 gse.getMessage());
      ioex.initCause(gse);
      // Don't throw a security exception, otherwise the MTS will never
      // retry to send the message.
      throw ioex;
    }

    if (log.isDebugEnabled()) {
      log.debug("protectHeader: " + sourceName +
                " -> " + targetName +
                " for agents " + sourceAgent + " -> " + targetAgent +
                " (" + policy + ")");
    }
    try {
      ProtectedObject po =
        encryptService.protectObject(rawData, sourceNode, targetNode, policy);
  
      oos.writeObject(po);
  
      if (log.isDebugEnabled()) {
        log.debug("protectHeader OK: " + sourceName +
                  " -> " + targetName);
      }
    } catch(GeneralSecurityException gse) {
      publishMessageFailure(sourceName, targetName, gse);
      IOException ioex = 
        new IOException("Unable to protect header:" + gse);
      ioex.initCause(gse);
      // Don't throw a security exception, otherwise the MTS will never
      // retry to send the message.
      throw ioex;
    } catch (Throwable t) {
      t.printStackTrace();
    }
    return baos.toByteArray();
  }

  /*
  public byte[] protectHeader(byte[] rawData,
			      MessageAddress source,
			      MessageAddress destination)
    throws GeneralSecurityException, IOException
  {
    if (!isInitialized) {
      setPolicyService();
    }

    CryptoPolicy policy =
       cps.getOutgoingPolicy(source.getAddress());

    // SR - 10/21/2002. UGLY & TEMPORARY FIX
    // The advance message clock uses an unsupported address type.
    // Since this is demo-ware, we are not encrypting those messages.
    if (destination.toAddress().endsWith("(MTS)")) {
	log.info("Outgoing postmaster message. Skipping encryption");
	return rawData;
    }

    if (policy == null) {
      if (log.isWarnEnabled()) {
	      log.warn("protectHeader NOK: " + source.toAddress()
		      + " -> " + destination.toAddress()
		      + " (No policy)");
      }
      GeneralSecurityException gse = new
	      GeneralSecurityException("Could not find message policy between "
				  + source.getAddress()
				  + " and " + destination.getAddress());
		  publishMessageFailure(source.toString(), destination.toString(),
        MessageFailureEvent.INVALID_POLICY, gse.toString());

      IOException ioex = new IOException("Unable to protect header:"
					 + gse.getMessage());
      ioex.initCause(gse);
      // Don't throw a security exception, otherwise the MTS will never
      // retry to send the message.
      throw ioex;
    }
    if (log.isDebugEnabled()) {
      log.debug("protectHeader: " + source.toAddress()
		    + " -> " + destination.toAddress()
 		    + " (" + policy.toString() + ")");
    }
    ByteArrayOutputStream baos = null;
    try {
      ProtectedObject po =
        encryptService.protectObject(rawData, source, destination, policy);
      baos = new ByteArrayOutputStream();
  
      ObjectOutputStream oos = new ObjectOutputStream(baos);
      oos.writeObject(po);
  
      if (log.isDebugEnabled()) {
        log.debug("protectHeader OK: " + source.toAddress()
  		+ " -> " + destination.toAddress());
      }
    }
    catch(GeneralSecurityException gse) {
      publishMessageFailure(source.toString(),
                            destination.toString(),
                            gse);
      IOException ioex = new IOException("Unable to protect header:"
	+ gse.getMessage());
      ioex.initCause(gse);
      // Don't throw a security exception, otherwise the MTS will never
      // retry to send the message.
      throw ioex;
    }
    return baos.toByteArray();
  }
  */
  /**
   * Verify the signed and/or encrypted header of an incoming message.
   *
   * @param rawData     The signed and/or encrypted header
   * @param source      The source of the message
   * @param destination The destination of the message
   * @return the header in the clear
   */
  public byte[] unprotectHeader(byte[] rawData,
				MessageAddress source,
				MessageAddress target)
    throws GeneralSecurityException, IOException
  {
//      return unprotectHeader(rawData, null, null, source, target, null);
     return rawData;
  }

  /**
   * Verify the signed and/or encrypted header of an incoming message.
   *
   * @param rawData     The signed and/or encrypted header
   * @param source      The source of the message
   * @param destination The destination of the message
   * @return the header in the clear
   */
  public byte[] unprotectHeader(byte[] rawData,
				MessageAddress sourceAgent,
				MessageAddress targetAgent,
                                MessageAddress sourceNode,
                                MessageAddress targetNode,
                                MessageAttributes attrs)
    throws GeneralSecurityException, IOException
  {
    if (isEncrypted(attrs)) {
      return rawData;
    }

    String sourceName = sourceNode.toAddress();
    String targetName = targetNode.toAddress();
    
    // SR - 10/21/2002. UGLY & TEMPORARY FIX
    // The advance message clock uses an unsupported address type.
    // Since this is demo-ware, we are not encrypting those messages.
    if (targetName.endsWith("(MTS)")) {
      targetName = targetName.substring(0, targetName.length() - 5);
      targetNode = MessageAddress.getMessageAddress(targetName);
      log.info("Incoming postmaster message. Protecting with node key");
    }

    if (!isInitialized) {
      setPolicyService();
    }

    ByteArrayInputStream bais = new ByteArrayInputStream(rawData);
    ObjectInputStream ois = new ObjectInputStream(bais);

    SecureMethodParam policy;
    try {
      policy = (SecureMethodParam) ois.readObject();
    } catch (Exception e) {
      if (log.isWarnEnabled()) {
        log.warn("unprotectHeader " + sourceName +
                 " -> " + targetName + " could not read policy", e);
      }
      throw new GeneralSecurityException("Could read policy for message " +
                                          "between " +
                                          sourceName + " and " + targetName +
                                         ": " + e.getMessage());
    }

    if (policy == null ||
        !cps.isReceivePolicyValid(sourceName, targetName, 
                                 policy, false, false)) {
      if (log.isWarnEnabled()) {
        log.warn("unprotectHeader " + sourceName +
                 " -> " + targetName + " policy " + policy +
                 " not allowed");
      }
      GeneralSecurityException gse = 
        new GeneralSecurityException("Could not use policy between " +
                                     sourceName + " and " + targetName);
      publishMessageFailure(sourceName, targetName,
                            MessageFailureEvent.INVALID_POLICY, 
                            gse.toString());
      throw gse;
    }     

    if (log.isDebugEnabled()) {
      log.debug("unprotectHeader: " + sourceName + " -> " + targetName +
                " (" + policy + ")");
    }

    ProtectedObject po = null;
    try {
      po = (ProtectedObject) ois.readObject();
    } catch (ClassNotFoundException e) {
      if (log.isWarnEnabled()) {
        log.warn("unprotectHeader " + sourceName + " -> " + targetName +
                 " (Class not found)");
      }
      throw new IOException("Can't unprotect header: " + e.getMessage());
    }
    try {
      byte[] b = (byte[])
        encryptService.unprotectObject(sourceNode, targetNode, po, policy);
      if (log.isDebugEnabled()) {
        log.debug("unprotectHeader OK: " + sourceName + " -> " + targetName);
      }
      return b;
    } catch (ClassCastException e) {
      throw new IOException("Found the wrong type of object in stream: " + e);
    } catch(DecryptSecretKeyException e) {
      // send the new certificate to the server
      AttributedMessage msg = getCertificateMessage(sourceNode, targetNode);
      if (msg != null) {
        SendQueue sendQ = MessageProtectionAspectImpl.getSendQueue();
        if (sendQ != null) {
          sendQ.sendMessage(msg);
          if (log.isInfoEnabled()) {
            log.info("Requesting that " + sourceName + " use new certificate");
          } 
        } else if (log.isWarnEnabled()) {
          log.warn("Could not send message to " + sourceName + 
                   " to use a new certificate. Make sure that " +
                   "org.cougaar.core.security.crypto.MessagePr" +
                   "otectionAspectImpl is used.");
        }
      }
      
      throw new RetryWithNewCertificateException(e.getMessage());
    } catch(GeneralSecurityException e) {
      publishMessageFailure(sourceName, targetName, e);
      throw e;
    }
  }

  private boolean isEncrypted(MessageAttributes attrs) {
    if (attrs == null) {
      return false;
    }
    Object encObj =
      attrs.getAttribute(AttributeConstants.ENCRYPTED_SOCKET_ATTRIBUTE);
    if (encObj == null) {
      return false;
    }

    if (encObj instanceof Boolean) {
      return ((Boolean) encObj).booleanValue();
    }

    if (encObj instanceof List) {
      List objs = (List) encObj;
      Iterator iter = objs.iterator();
      encObj = null;
      Boolean altValue = null;
      while (iter.hasNext()) {
        encObj = iter.next();
        // take Boolean values first
        if (encObj instanceof Boolean) {
          return ((Boolean) encObj).booleanValue();
        }
        if (encObj != null && altValue == null) {
          String val = encObj.toString();
          if ("true".equalsIgnoreCase(val)) {
            altValue = Boolean.TRUE;
          } else if ("false".equalsIgnoreCase(val)) {
            altValue = Boolean.FALSE;
          }
        }
      }
      if (altValue != null) {
        return altValue.booleanValue();
      }
      return false;
    }
    log.warn("Unexpected class for ENCRYPTED_SOCKET_ATTRIBUTE: " +
             encObj.getClass().getName());
    return false; // not a valid attribute
  }

  /** 
   * Gets a stream to encrypt and/or sign outgoing messages
   *
   * This method is called once for each outgoing message.
   * The implementation of this service must construct a
   * ProtectedOutputStream, which is a special kind of FilterOutputStream.
   * The service client (MTS) serializes a Message to this 
   * ProtectedOutputStream. The implementation of the service will in turn
   * write data to the 'os' stream it was given at creation time.
   * When the Message has been completely serialized and written 
   * to the ProtectedOutputStream, the service client calls the finish()
   * method of the ProtectedOutputStream.
   *
   * The first byte of the ProtectedOutputStream should be the first byte
   * of the (serialized) message content.
   *
   * Since messages may be resent, the method may be called multiple times
   * for the same message, but this is in a different context.
   *
   * @param os The output stream containing encrypted and/or signed data
   * @param source      The source of the outgoing message
   * @param destination The destination of the outgoing message
   * @param attrs       The attributes of the outgoing message
   * @return A filter output stream
   */
  public ProtectedOutputStream getOutputStream(OutputStream os,
					       MessageAddress source,
					       MessageAddress destination,
					       MessageAttributes attrs)
    throws IOException
  {
    if (log.isDebugEnabled()) {
      log.debug("getOutputStream: " + source.toAddress()
		+ " -> " + destination.toAddress());
    }
    if (!isInitialized) {
      setPolicyService();
    }

    try {
      SecureMethodParam policy = 
        cps.getSendPolicy(source.getAddress(), destination.getAddress());
      if (log.isDebugEnabled()) {
        log.debug("Policy = " + policy);
      }
      if (policy == null) {
        log.error("Policy is null. The message cannot be protected. " +
                  "Likely cause is DAML policy enforcer.");
        throw new IOException("Protection policy is null");
      }
      boolean encryptedSocket = isEncrypted(attrs);
      Object link = 
        attrs.getAttribute(MessageProtectionAspectImpl.TARGET_LINK);
      log.debug("returning encrypted service");
      return encryptService.
        protectOutputStream(os, policy, source, destination, encryptedSocket,
                            link);
    } catch (DecryptSecretKeyException e) {
      AttributedMessage msg = getCertificateMessage(source, destination);
      if (msg != null) {
        SendQueue sendQ = MessageProtectionAspectImpl.getSendQueue();
        if (sendQ != null) {
          sendQ.sendMessage(msg);
          if (log.isInfoEnabled()) {
            log.info("Requesting that " + source + " use new certificate");
          } 
        } else if (log.isWarnEnabled()) {
          log.warn("Could not send message to " + source + 
                   " to use a new certificate. Make sure that " +
                   "org.cougaar.core.security.crypto.MessagePr" +
                   "otectionAspectImpl is used.");
        }
      }
      throw new RetryWithNewCertificateException(e.getMessage());
    } catch (GeneralSecurityException e) {
      log.debug("Got an error when protecting output stream", e);
      String reason = MessageFailureEvent.UNKNOWN_FAILURE;
    
      // need to extract the reason of failure from the exception message
      try {
        Object []objs = exceptionFormat.parse(e.getMessage());
        if(objs.length == 1) {
          reason = (String)objs[0];
        }
      } catch(ParseException pe) {
        // eat this exception?
      }
      FailureEvent event = new MessageFailureEvent(source.toString(),
                                                   destination.toString(),
                                                   reason,
                                                   e.toString());
      if (eventPublisher != null) {
        eventPublisher.publishEvent(event);
      }
      throw new IOException(reason);
    } catch (Exception e) {
      log.debug("Got unexpected exception", e);
      return null;
    }
  }

  /** 
   * Gets a stream to verify incoming messages
   *
   * This method is called once for each incoming message.
   * The implementation of this service must construct a
   * ProtectedInputStream, which is a special kind of FilterInputStream.
   * The service reads an encrypted message from the ProtectedInputStream.
   * The service client (MTS) calls the finishInput() method when all the
   * message has been read.
   * The service client verifies the message. The service client reads
   * the clear-text message from the 'is' input stream.
   *
   * The first byte of the ProtectedInputStream should be the first byte
   * of the (serialized) message content.
   *
   * Since messages may be resent, the method may be called multiple times
   * for the same message, but this is in a different context.
   *
   * @param os The input stream containing the verified clear-text message
   * @param source      The source of the incoming message
   * @param destination The destination of the incoming message
   * @param attrs       The attributes of the incoming message
   * @return A filter intput stream
   */
  public ProtectedInputStream getInputStream(InputStream is,
					     MessageAddress source,
					     MessageAddress destination,
					     MessageAttributes attrs)
    throws IOException
  {
    if (log.isDebugEnabled()) {
      log.debug("getInputStream: " + source.toAddress()
		+ " -> " + destination.toAddress());
    }

    if (!isInitialized) {
      setPolicyService();
    }

    try {
      boolean encryptedSocket = isEncrypted(attrs);
      String strPrinc = null;
      Principal principal = KeyRingSSLServerFactory.getPrincipal();
      if (principal != null) {
        strPrinc = principal.getName();
      }
      return encryptService.
        protectInputStream(is, source, destination,
                           encryptedSocket, strPrinc, cps);
    } catch (GeneralSecurityException e) {
      String reason = MessageFailureEvent.UNKNOWN_FAILURE;
    
      // need to extract the reason of failure from the exception message
      try {
        Object []objs = exceptionFormat.parse(e.getMessage());
        if(objs.length == 1) {
          reason = (String)objs[0];
        }
      } catch(ParseException pe) {
        // eat this exception?
      }
      FailureEvent event = new MessageFailureEvent(source.toString(),
                                                   destination.toString(),
                                                   reason,
                                                   e.toString());
      if (eventPublisher != null) {
        eventPublisher.publishEvent(event);
      }
      throw new IOException(reason);
    } catch (Exception e) {
      log.warn("Unexpected Exception when reading input stream", e);
      return null;
    }
  }
  
  /**
   * publish a message failure idmef alert
   */
  private void publishMessageFailure(String source, String target,
    String reason, String data) {
    FailureEvent event = new MessageFailureEvent(source,
                                                 target,
                                                 reason,
                                                 data);
    if(eventPublisher != null) {
      eventPublisher.publishEvent(event); 
    }
    else {
      if(log.isDebugEnabled()) {
        log.debug("EventPublisher uninitialized, unable to publish event:\n" + event);
      }
    }  
  }
  
  private void publishMessageFailure(String source, String target,
    GeneralSecurityException gse) {
    String reason = MessageFailureEvent.UNKNOWN_FAILURE;
    // need to extract the reason of failure from the exception message
    try {
      Object []objs = exceptionFormat.parse(gse.getMessage());
      if(objs.length == 1) {
        reason = (String)objs[0];
      }
    }
    catch(ParseException pe) {
      // eat this exception?
    }
    publishMessageFailure(source,
                          target,
                          reason,
                          gse.toString());  
  }

  public static class RetryWithNewCertificateException extends IOException {
    public RetryWithNewCertificateException() {
    }

    public RetryWithNewCertificateException(String message) {
      super(message);
    }
  }

  // for certificate requests
  class CertificateRequestMessage extends Message {
    public CertificateRequestMessage(MessageAddress src, MessageAddress dest) {
      super(src, dest);
    } 
  }
}
