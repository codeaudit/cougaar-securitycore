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


package org.cougaar.core.security.services.crypto;

import org.cougaar.core.component.Service;
import org.cougaar.core.mts.Message;

/** Cryptographic Service used to cryptographically protect incoming
 * and outgoing messages.
 * This service should be called by the transport service for
 * all Cougaar messages.
 */
public interface MessageProtectionService extends Service {

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
