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

// Overlay
import org.cougaar.core.security.coreservices.identity.TransferableIdentity;

public class PublicKeyEnvelope
  implements Serializable
{
  /** The encrypted symmetric key used to encrypt an object.
   */
  private SealedObject encryptedSymmetricKey;

  /** The certificate used to encrypt the symmetric key.
   */
  private X509Certificate receiver;

  /** The certificate corresponding to the private key that was used
      to sign the object.
   */
  private X509Certificate sender;

  /** The encrypted object
   */
  private SealedObject encryptedObject;

  public PublicKeyEnvelope(X509Certificate asender,
			   X509Certificate areceiver,
			   SealedObject sKey,
			   SealedObject encObj) {
    encryptedSymmetricKey = sKey;
    receiver = areceiver;
    sender = asender;
    encryptedObject = encObj;
  }

  public SealedObject getEncryptedSymmetricKey() {
    return encryptedSymmetricKey;
  }

  public X509Certificate getReceiver() {
    return receiver;
  }

  public X509Certificate getSender() {
    return sender;
  }

  public SealedObject getEncryptedObject() {
    return encryptedObject;
  }
}
