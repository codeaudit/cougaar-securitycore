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


package org.cougaar.core.security.coreservices.crypto;

import java.io.InputStream;
import java.io.OutputStream;

// Cougaar core services
import org.cougaar.core.component.Service;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageAttributes;

/** Cryptographic Service used to cryptographically protect incoming
 * and outgoing messages.
 * This service should be called by the transport service for
 * all Cougaar messages.
 */
public interface MessageProtectionService extends Service {

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
   *    - The first byte of the input stream should be the first byte
   *      of the message content.
   * 5) The service returns an output stream that contains the encrypted
   *    message.
   * 6) The service reads data from the input stream.
   * 6) The aspect reads data from the ProtectedOutputStream.
   *
   * @param rawData     The unencrypted header
   * @param source      The source of the message
   * @param destination The destination of the message
   * @return the protected header (sign and/or encrypted)
   */
  public byte[] protectHeader(byte[] rawData,
			      MessageAddress source,
			      MessageAddress destination);

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
				MessageAddress destination);

  public ProtectedOutputStream getOutputStream(OutputStream os,
					       MessageAddress src,
					       MessageAddress dst,
					       MessageAttributes attrs);

  public ProtectedInputStream getInputStream(InputStream is,
					     MessageAddress src,
					     MessageAddress dst,
					     MessageAttributes attrs);

  /** 
   * Take an unprotected message and apply appropriate cryptographic
   * mechanisms.
   * For instance, messages may be signed and encrypted.
   * The transport service should call protectMessage for all
   * outgoing messages, just before giving the message to the
   * underlying tranport protocol.
   *
   * @param  m - the unprotected message
   * @return the protected message, according to the crypto policy
   */
  public Message protectMessage(Message m);

  /** 
   * Take a cryptographically protected message and restore the
   * original message.
   * The transport service should call unprotectMessage for all
   * incoming messages.
   *
   * @param  m - the protected message
   * @return the unprotected message - May be null if the message 
   * does not comply with the policy.
   */
  public Message unprotectMessage(Message m);

}
