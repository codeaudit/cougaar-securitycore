/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.crypto;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.cert.X509Certificate;
import java.util.StringTokenizer;

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

  private void writeObject(ObjectOutputStream out) throws IOException {
    boolean enc = (_policy.secureMethod == SecureMethodParam.ENCRYPT ||
                   _policy.secureMethod == SecureMethodParam.SIGNENCRYPT);
    boolean sign = (_policy.secureMethod == SecureMethodParam.SIGN ||
                   _policy.secureMethod == SecureMethodParam.SIGNENCRYPT);
    out.writeInt(_policy.secureMethod);
    if (enc) {
      out.writeObject(_policy.symmSpec);
      out.writeObject(_encryptedSymmetricKey);
      out.writeObject(_encryptedSymmetricKeySender);
    }
    if (sign || enc) {
      out.writeObject(_policy.asymmSpec);
      out.writeObject(_receiver);
      out.writeObject(_sender);
    }
    if (sign) {
      out.writeObject(_policy.signSpec);
    }
  }

  private void readObject(ObjectInputStream is) 
    throws IOException, ClassNotFoundException {
    _policy = new SecureMethodParam();
    _policy.secureMethod = is.readInt();
    boolean enc = (_policy.secureMethod == SecureMethodParam.ENCRYPT ||
                   _policy.secureMethod == SecureMethodParam.SIGNENCRYPT);
    boolean sign = (_policy.secureMethod == SecureMethodParam.SIGN ||
                   _policy.secureMethod == SecureMethodParam.SIGNENCRYPT);
    
    if (enc) {
      _policy.symmSpec = (String) is.readObject();
      _encryptedSymmetricKey = (byte[]) is.readObject();
      _encryptedSymmetricKeySender = (byte[]) is.readObject();
    }
    if (sign || enc) {
      _policy.asymmSpec = (String) is.readObject();
      _receiver = (X509Certificate) is.readObject();
      _sender = (X509Certificate[]) is.readObject();
    }
    if (sign) {
      _policy.signSpec = (String) is.readObject();
    }
  }
}
