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

package org.cougaar.core.security.dataprotection;

import java.io.Serializable;
import java.security.cert.X509Certificate;

/**
 * The content of the request that goes from the Data Protection service to the
 * Persistence Management Agent.
 */
public class DataProtectionRequestContent implements Serializable
{
  /** The collection of keys that were used to encrypt the persisted blackboard. */
  private DataProtectionKeyCollection keyCollection;

  /** The certificate chain of the entity which asks to unlock the key. */
  private X509Certificate[] requestorCertificateChain;

  public DataProtectionRequestContent(DataProtectionKeyCollection kc,
				      X509Certificate[] certChain) {
    keyCollection = kc;
    requestorCertificateChain = certChain;
  }

  /** Return the collection of keys that were used to encrypt the persisted blackboard. */
  public DataProtectionKeyCollection getKeyCollection() {
    return keyCollection;
  }

  /** Return the certificate chain of the entity which asks to unlock the key. */
  public X509Certificate[] getRequestorCertificateChain() {
    return requestorCertificateChain;
  }
}
