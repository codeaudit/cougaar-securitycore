/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
import org.cougaar.core.service.identity.TransferableIdentity;

// Cougaar core infrastructure
import org.cougaar.core.mts.MessageAddress;

public class KeyIdentity
  extends PublicKeyEnvelope
  implements TransferableIdentity
{

  public KeyIdentity(X509Certificate asender[],
		     X509Certificate areceiver,
		     MessageAddress areceiverAddress,
		     MessageAddress asenderAddress,
		     SecureMethodParam policy,
		     byte[] sKeySender,
		     byte[] sKeyReceiver,
		     Object encObj) {
    super(asender, areceiver, areceiverAddress, asenderAddress, policy, sKeySender, sKeyReceiver, encObj);
  }
}
