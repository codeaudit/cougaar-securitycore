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

import java.security.cert.X509Certificate;

import org.cougaar.core.mts.MessageAddress;

public class PublicKeyEnvelope
  extends ProtectedObject
{
  /** The encrypted symmetric key used to encrypt an object.
   *  This key is encrypted with the public key of the target.
   */
  private byte[] encryptedSymmetricKey;

  /** The encrypted symmetric key used to encrypt an object.
   *  This key is encrypted with the public key of the sender.
   *  It is the same session key as the one in encryptedSymmetricKey,
   *  however it is encrypted with the sender. This allows the
   *  sender to recover the object if necessary.
   */
  private byte[] encryptedSymmetricKeySender;

  /** The certificate used to encrypt the symmetric key.
   */
  private X509Certificate receiver;

  /** The certificate corresponding to the private key that was used
      to sign the object.
   */
  private X509Certificate sender[];

  private MessageAddress receiverAddress;
  private MessageAddress senderAddress;

  public PublicKeyEnvelope(X509Certificate asender[],
			   X509Certificate areceiver,
			   MessageAddress asenderAddress,
			   MessageAddress areceiverAddress,
			   SecureMethodParam policy,
			   byte[] sKeySender,
			   byte[] sKeyReceiver,
			   Object encObj) {
    super(policy, encObj);
    encryptedSymmetricKey = sKeyReceiver;
    encryptedSymmetricKeySender = sKeySender;

    sender = asender;
    receiver = areceiver;

    receiverAddress = areceiverAddress;
    senderAddress = asenderAddress;
  }

  public byte[] getEncryptedSymmetricKey() {
    return encryptedSymmetricKey;
  }

  public byte[] getEncryptedSymmetricKeySender() {
    return encryptedSymmetricKeySender;
  }

  public X509Certificate getReceiver() {
    return receiver;
  }
  public X509Certificate[] getSender() {
    return sender;
  }

  public MessageAddress getReceiverAddress() {
    return receiverAddress;
  }
  public MessageAddress getSenderAddress() {
    return senderAddress;
  }
}
