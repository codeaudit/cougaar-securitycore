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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.AttributeConstants;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.ProtectedInputStream;
import org.cougaar.core.mts.ProtectedOutputStream;
import org.cougaar.mts.base.SendQueue;
import org.cougaar.mts.std.AttributedMessage;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.MessageFailureEvent;
import org.cougaar.core.security.monitoring.plugin.MessageFailureSensor;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.ssl.KeyRingSSLServerFactory;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.MessageProtectionService;
import org.cougaar.core.service.wp.Callback;
import org.cougaar.core.service.wp.Response;
import org.cougaar.core.service.wp.WhitePagesService;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

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
  private WhitePagesService _wps = null;

  private LoggingService log;
  private boolean isInitialized = false;
  // event publisher to publish message failure
  //private EventPublisher eventPublisher = null;
  private MessageFormat exceptionFormat = new MessageFormat("{0} -");
  private MessageAddress _localNode = null;
  private static final String MPA_CLASSNAME = 
    MessageProtectionAspectImpl.class.getName();
  private static final String FILTERS_ATTRIBUTE = "Filters";

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

    // Retrieve Encryption service
    _wps = (WhitePagesService)
      serviceBroker.getService(this, WhitePagesService.class, null);

    if (_wps == null) {
      log.warn("Unable to get WhitePagesService");
      throw new RuntimeException("MessageProtectionService. No WhitePagesService");
    }

    NodeIdentificationService nis = (NodeIdentificationService)
      serviceBroker.getService(this, NodeIdentificationService.class, null);
    if (nis == null) {
      log.warn("Unable to getNodeIdentificationService ");
      throw new RuntimeException("MessageProtectionService. No NodeIdentificationService");
    }
    _localNode = nis.getMessageAddress();
  }

  /*
  // method used to initialize event publisher
  public synchronized void addPublisher(EventPublisher publisher) {
    if(eventPublisher == null) {
      eventPublisher = publisher;
    }
  }
  */
  
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
      msg.setAttribute(MessageProtectionAspectImpl.NEW_CERT, certificate);
      msg.setContentsId(certificate.hashCode());
      return msg;
    } catch (Exception e) {
      log.warn("Couldn't find certificate for " + destAddr +
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
   * @param attributes  The attributes to be protected
   * @param source      The source of the message
   * @param target      The destination of the message
   * @return the protected header (sign and/or encrypted)
   */
  public byte[] protectHeader(MessageAttributes attributes,
			      MessageAddress source,
			      MessageAddress target)
    throws GeneralSecurityException, IOException
  {
    // first get the target node
    MessageAddress targetNode = getNodeAddress(target);

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    ObjectOutputStream    oout = new ObjectOutputStream(bout);

    boolean encrypted = isEncrypted(attributes);
    oout.writeBoolean(encrypted);
    if (encrypted) {
      // no need for signature or encryption -- SSL is good!
      oout.writeObject(attributes);
      oout.close();
      return bout.toByteArray();
    }

    String sourceName = _localNode.toAddress();
    String targetName = targetNode.toAddress();

    if (!isInitialized) {
      setPolicyService();
    }
    
    SecureMethodParam policy = cps.getSendPolicy(sourceName, targetName);

    if (policy == null) {
      if (log.isWarnEnabled()) {
        log.warn("protectHeader: " + sourceName +
                 " -> " + targetName + 
                 " for agents " + source + " -> " + target +
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

    oout.writeObject(policy);

    if (log.isDebugEnabled()) {
      log.debug("protectHeader: " + sourceName +
                " -> " + targetName +
                " for agents " + source + " -> " + target +
                " (" + policy + ")");
    }
    
    try {
      ProtectedObject po =
        encryptService.protectObject(attributes, _localNode, targetNode, 
                                     policy);
  
      oout.writeObject(po);
  
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
    }
    oout.close();
    return bout.toByteArray();
  }

  private MessageAddress getNodeAddress(MessageAddress agent) 
    throws IOException {
    
    return agent;

    /* There are problems with the following because there is no
     * way to detect the WhitePagesService agent name without
     * going through the WhitePagesService. Chicken-and-egg, eh?
     * Actually, there are some work-arounds, but they aren't
     * really worth it, so I'm not going to bother...
     */
    /*
    MessageAddress addr;
    if (agent.equals(_localNode)) {
      return agent;
    }
    
    try {
      AddressEntry entry = _wps.get(agent.toAddress(), "topology", -1);
      if (entry != null) {
        addr = MessageAddress.getMessageAddress(entry.getName());
      } else {
        // try a callback to force a lookup...
        _wps.get(agent.toAddress(), "topology", LOOKUP_CALLBACK);
        addr = null;
      }
    } catch (Exception e) {
      addr = null;
    }
    if (addr == null) {
      throw new IOException("Message cannot be accepted until node name can be found");
    }
    return addr;
    */
  }

  /**
   * Verify the signed and/or encrypted header of an incoming message.
   *
   * @param rawData     The signed and/or encrypted header
   * @param source      The source of the message
   * @param destination The destination of the message
   * @return the header in the clear
   */
  /* not needed anymore...
  public byte[] unprotectHeader(byte[] rawData,
				MessageAddress source,
				MessageAddress target)
    throws GeneralSecurityException, IOException
  {
    try {
      MessageAttributes attrs = unprotectHeader2(rawData, source, target);
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      ObjectOutputStream oout = new ObjectOutputStream(bout);
      oout.writeObject(attrs);
      oout.close();
      return bout.toByteArray();
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      return null;
    }
  }
  */

  /**
   * Verify the signed and/or encrypted header of an incoming message.
   *
   * @param rawData     The signed and/or encrypted header
   * @param source      The source of the message
   * @param target      The destination of the message
   * @return The message attributes associated with the rawData
   */
  public MessageAttributes unprotectHeader(byte[] rawData,
                                           MessageAddress source,
                                           MessageAddress target)
    throws GeneralSecurityException, IOException
  {
    if (rawData == null) {
      throw new IOException("Empty header");
    }
    if (!isInitialized) {
      setPolicyService();
    }

    ByteArrayInputStream bin = new ByteArrayInputStream(rawData);
    ObjectInputStream oin = new ObjectInputStream(bin);
    
    MessageAttributes attrs;
    boolean encrypted = oin.readBoolean();
    if (encrypted) {
      // FIXME!! This is a hack! There should be a way to determine
      // if the thread is an internal route or not other than by
      // using the thread group name
      ThreadGroup tg = Thread.currentThread().getThreadGroup();
      if ((tg != null && !tg.getName().equals("RMI Runtime")) ||
          KeyRingSSLServerFactory.getPrincipal() != null) {
        try {
          attrs = (MessageAttributes) oin.readObject();
        } catch (Exception e) {
          if (log.isWarnEnabled()) {
            log.warn("unprotectHeader (plain) " + source +
                     " -> " + target + " could not read header", e);
          }
          throw new GeneralSecurityException("Could read unprotected message " +
                                             "between " +
                                             source + " and " + target +
                                             ": " + e.getMessage());
        }
      } else {
        if (log.isWarnEnabled()) {
          log.warn("unprotectHeader (plain) " + source +
                   " -> " + target + " clear channel used");
          }
          throw new GeneralSecurityException("Could read unprotected message " +
                                             "between " +
                                             source + " and " + target +
                                             ": clear channel used");
      }
    } else {
      MessageAddress sourceNode = getNodeAddress(source);
      String sourceName = sourceNode.toAddress();
      String targetName = _localNode.toAddress();
    
      SecureMethodParam policy;
      try {
        policy = (SecureMethodParam) oin.readObject();
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
        po = (ProtectedObject) oin.readObject();
      } catch (ClassNotFoundException e) {
        if (log.isWarnEnabled()) {
          log.warn("unprotectHeader " + sourceName + " -> " + targetName +
                   " (Class not found)");
        }
        throw new IOException("Can't unprotect header: " + e.getMessage());
      }
      try {
        attrs = (MessageAttributes)
          encryptService.unprotectObject(sourceNode, _localNode, po, policy);
        if (log.isDebugEnabled()) {
          log.debug("unprotectHeader OK: " + sourceName + " -> " + targetName);
        }
      } catch (ClassCastException e) {
        throw new IOException("Found the wrong type of object in stream: " + e);
      } catch(DecryptSecretKeyException e) {
        // send the new certificate to the server
        AttributedMessage msg = getCertificateMessage(sourceNode, _localNode);
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
    checkAspectChain(attrs);
    return attrs;
  }

  private void checkAspectChain(MessageAttributes attrs) {
    Collection c = (Collection) attrs.getAttribute("Filters");
    if (c == null) {
      c = new ArrayList();
      attrs.setAttribute(FILTERS_ATTRIBUTE, c);
    }
    Iterator iter = c.iterator();
    while (iter.hasNext()) {
      Object val = iter.next();
      if (val.equals(MPA_CLASSNAME)) {
        return;
      }
    }
    // couldn't find it in the list.. add it!
    log.debug("Adding " + MPA_CLASSNAME + " to aspect chain");
    attrs.pushValue(FILTERS_ATTRIBUTE, MPA_CLASSNAME);
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

    /* as of 10.4.3 -- hack is no longer needed
    // SR - 10/21/2002. UGLY & TEMPORARY FIX
    // The advance message clock uses an unsupported address type.
    // Since this is demo-ware, we are not encrypting those messages.
    if (source.toAddress().endsWith("(MTS)")) {
      String name = source.toAddress();
      name = name.substring(0, name.length() - 5);
      source = MessageAddress.getMessageAddress(name);
      log.info("Outgoing source postmaster message. Protecting with node key");
    }
    if (destination.toAddress().endsWith("(MTS)")) {
      String name = destination.toAddress();
      name = name.substring(0, name.length() - 5);
      destination = MessageAddress.getMessageAddress(name);
      log.info("Outgoing target postmaster message. Protecting with node key");
    }
    */
    try {
      boolean encryptedSocket = isEncrypted(attrs);
      log.debug("returning encrypted service");
      return new ProtectedMessageOutputStream(os, source, destination, 
                                              encryptedSocket, serviceBroker);
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
    } catch (NoKeyAvailableException e) {
      throw new IOException(e.getMessage());
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
      /*
      if (eventPublisher != null) {
        eventPublisher.publishEvent(event);
      }
      */
      MessageFailureSensor.publishEvent(event);
      throw new IOException(reason);
//     } catch (Exception e) {
//       log.debug("Caught unexpected Exception", e);
//       return null;
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
      log.debug("attributes as string = " + attrs.getAttributesAsString());
    }

    if (!isInitialized) {
      setPolicyService();
    }

    /* as of 10.4.3 -- hack is no longer needed
    // SR - 10/21/2002. UGLY & TEMPORARY FIX
    // The advance message clock uses an unsupported address type.
    // Since this is demo-ware, we are not encrypting those messages.
    if (source.toAddress().endsWith("(MTS)")) {
      String name = source.toAddress();
      name = name.substring(0, name.length() - 5);
      source = MessageAddress.getMessageAddress(name);
      log.info("Incoming source postmaster message. Protecting with node key");
    }
    if (destination.toAddress().endsWith("(MTS)")) {
      String name = destination.toAddress();
      name = name.substring(0, name.length() - 5);
      destination = MessageAddress.getMessageAddress(name);
      log.info("Incoming target postmaster message. Protecting with node key");
    }
    */

    boolean encryptedSocket = isEncrypted(attrs);
    try {
      return new ProtectedMessageInputStream(is, source, destination,
                                             encryptedSocket,
                                             serviceBroker);
    } catch (IncorrectProtectionException e) {
      // The stream has already reported the error. Just throw
      // an IOException
      FailureEvent event = new MessageFailureEvent(source.toString(),
                                                   destination.toString(),
                                                   e.getMessage(),
                                                   e.toString());
      MessageFailureSensor.publishEvent(event);
      throw new IOException(e.getMessage());
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
      /*
      if (eventPublisher != null) {
        eventPublisher.publishEvent(event);
      }
      */
      MessageFailureSensor.publishEvent(event);
      throw new IOException(reason);
    } catch (MessageDumpedException e) {
      if (log.isInfoEnabled()) {
        log.info("Got message terminated early from " +
                 source + " to " + destination + ": " + e.getMessage());
      }
      throw e;
//     } catch (Exception e) {
//       log.warn("Unexpected Exception when reading input stream", e);
//       return null;
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
    /*
    if(eventPublisher != null) {
      eventPublisher.publishEvent(event); 
    }
    else {
      if(log.isDebugEnabled()) {
        log.debug("EventPublisher uninitialized, unable to publish event:\n" + event);
      }
    } 
    */
    MessageFailureSensor.publishEvent(event); 
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

  private static final Callback LOOKUP_CALLBACK = new Callback() {
      public void execute(Response res) {
      }
    };
}
