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
import java.security.cert.*;

public class KeySet
  implements java.io.Serializable
{
  private PrivateKey[]  privateKeys;
  private X509Certificate[] certificates;

  public KeySet(PrivateKey[] privateKeys,
		X509Certificate[] certificates) {
    if ((privateKeys == null) || (privateKeys.length ==0) ||
	(certificates == null) || (certificates.length == 0)) {
      throw new IllegalArgumentException("Keys are not provided");
    }

    if (privateKeys.length != certificates.length) {
      throw new
	IllegalArgumentException("Number of keys and certs do not match");
    }

    this.privateKeys = privateKeys;
    this.certificates = certificates;
  }

  public PrivateKey[] getPrivateKeys() {
    return privateKeys;
  }

  public X509Certificate[] getCertificates() {
    return certificates;
  }
}
