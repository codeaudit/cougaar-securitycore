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

// Cougaar core services
import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.ProtectedInputStream;
import org.cougaar.core.mts.ProtectedOutputStream;
import org.cougaar.core.service.MessageProtectionService;

// Cougaar security services
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

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

  private int infoLevel = 0;
  private boolean debug = false;

  public MessageProtectionServiceImpl(ServiceBroker sb) {
    serviceBroker = sb;

    String db = secprop.getProperty(secprop.TRANSPORT_DEBUG);
    if ( db!=null && (db.equalsIgnoreCase("true") ||
		      db.indexOf("security")>=0) ) debug=true;
    infoLevel = (Integer.valueOf(secprop.getProperty(secprop.SECURITY_DEBUG,
						     "0"))).intValue();
    if (infoLevel > 0) {
      System.out.println("Initializing MessageProtectionServiceImpl");
    }

    // Retrieve security properties service
    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this, SecurityPropertiesService.class, null);

    // Retrieve KeyRing service
    this.keyRing = (KeyRingService)
      serviceBroker.getService(
	this, KeyRingService.class, null);

    // Retrieve Encryption service
    this.encryptService = (EncryptionService)
      serviceBroker.getService(this, EncryptionService.class, null);
    if (encryptService == null) {
      System.out.println("Unable to get Encryption service");
      throw new RuntimeException("MessageProtectionService. No encryption service");
    }

    // Retrieve policy service
    cps = (CryptoPolicyService)
      serviceBroker.getService(this, CryptoPolicyService.class, null);
    if (cps == null) {
      System.out.println("Unable to get crypto policy service");
      throw new RuntimeException("MessageProtectionService. No crypto policy service");
    }
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
			      MessageAddress destination) {

    SecureMethodParam policy =
      cps.getSendPolicy(source.getAddress() + ":"
			+ destination.getAddress());
    if (policy == null) {
       throw new RuntimeException("Could not find message policy between "
	+ source.getAddress() + " and " + destination.getAddress());
    }     

    ProtectedObject po =
      encryptService.protectObject(rawData, source, destination, policy);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    try {
      ObjectOutputStream oos = new ObjectOutputStream(baos);
      oos.writeObject(po);
    }
    catch (IOException e) {
    }
    return baos.toByteArray();
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
				MessageAddress source,
				MessageAddress destination) {
    SecureMethodParam policy =
      cps.getReceivePolicy(source.toAddress()
			   +":"
			   +destination.toAddress());
    if (policy == null) {
       throw new RuntimeException("Could not find message policy between "
	+ source.getAddress() + " and " + destination.getAddress());
    }     

    ByteArrayInputStream bais = new ByteArrayInputStream(rawData);
    ProtectedObject po = null;
    try {
      ObjectInputStream ois = new ObjectInputStream(bais);
      po = (ProtectedObject) ois.readObject();
    }
    catch (IOException e) {
    }
    catch (ClassNotFoundException e) {
    }

    Object o =
      encryptService.unprotectObject(source, destination, po, policy);

    return (byte[])o;
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
					       MessageAttributes attrs) {
    MessageOutputStream pos =
      new MessageOutputStream(os, encryptService, cps, source, destination);
    return pos;
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
					     MessageAttributes attrs) {

    MessageInputStream pis =
      new MessageInputStream(is, encryptService, cps, source, destination);
    return pis;
  }
}
