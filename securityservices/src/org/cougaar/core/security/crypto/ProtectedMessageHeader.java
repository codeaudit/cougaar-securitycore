/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */

package org.cougaar.core.security.crypto;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.io.Serializable;
import javax.crypto.SealedObject;
import java.security.cert.X509Certificate;
import java.util.*;

// Cougaar core infrastructure
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.SimpleMessageAddress;

public class ProtectedMessageHeader implements java.io.Serializable {
  /** The encrypted symmetric key used to encrypt an object.
   *  This key is encrypted with the public key of the target.
   */
  private byte[] _encryptedSymmetricKey;

  /** The encrypted symmetric key used to encrypt an object.
   *  This key is encrypted with the public key of the sender.
   *  It is the same session key as the one in encryptedSymmetricKey,
   *  however it is encrypted with the sender. This allows the
   *  sender to recover the object if necessary.
   */
  private byte[] _encryptedSymmetricKeySender;

  /** The certificate used to encrypt the symmetric key.
   */
  private X509Certificate _receiver;

  /** The certificate corresponding to the private key that was used
   *  to sign the object.
   */
  private X509Certificate _sender[];

  /**
   * The protection method
   */
  private SecureMethodParam _policy;

  public ProtectedMessageHeader(X509Certificate sender[],
                                X509Certificate receiver,
                                SecureMethodParam policy,
                                byte[] sKey,
                                byte[] sKeySender) {
    _encryptedSymmetricKey = sKey;
    _encryptedSymmetricKeySender = sKeySender;

    _sender = sender;
    _receiver = receiver;
    _policy = policy;
  }

  public byte[] getEncryptedSymmetricKey() {
    return _encryptedSymmetricKey;
  }

  public byte[] getEncryptedSymmetricKeySender() {
    return _encryptedSymmetricKeySender;
  }

  public X509Certificate getReceiver() {
    return _receiver;
  }
  public X509Certificate[] getSender() {
    return _sender;
  }

  public SecureMethodParam getPolicy() {
    return _policy;
  }

  public MessageAddress getReceiverAddress() {
    if (_receiver == null) {
      return null;
    }
    return SimpleMessageAddress.getSimpleMessageAddress(toCN(_receiver));
  }
  public MessageAddress getSenderAddress() {
    if (_sender == null) {
      return null;
    }
    return SimpleMessageAddress.getSimpleMessageAddress(toCN(_sender[0]));
  }

  public String getReceiverName() {
    if (_receiver == null) {
      return null;
    }
    return toCN(_receiver);
  }

  public String getSenderName() {
    if (_sender == null) {
      return null;
    }
    return toCN(_sender[0]);
  }

  private static String toCN(X509Certificate x509) {
    if (x509 == null) {
      return null;
    }
    String dn = x509.getSubjectX500Principal().getName();
    StringTokenizer tzer = new StringTokenizer(dn, "=", true);
    int index = 0;
    while (tzer.hasMoreTokens()) {
      String name = tzer.nextToken();
      String value;
      index += name.length();
      tzer.nextToken(); // eliminate the '='
      index++;

      if (dn.length() > index && dn.charAt(index) == '"') {
        // until next quote char
        index += tzer.nextToken("\"").length();
        value = tzer.nextToken("\""); // capture the value
        index += value.length();
        index += tzer.nextToken("\"").length(); // skip the second quote char
      } else {
        value = tzer.nextToken(",");
        index += value.length();
      }
      if (name.equals("CN")) {
        return value;
      }
      // now skip the ', ' if it exists
      if (tzer.hasMoreTokens()) {
        tzer.nextToken(" ");
        tzer.nextToken(" ");
        index+=2;
      }
    }
    return null;
  }

  public String toString() {
    return "ProtectedMessageHeader " +
      ((_sender == null) 
       ? "null" 
       : _sender[0].getSubjectX500Principal().getName()) +
      " -> " + 
      ((_receiver == null)
       ? "null" 
       : _receiver.getSubjectX500Principal().getName()) +
      ": " + _policy;
  }
}
