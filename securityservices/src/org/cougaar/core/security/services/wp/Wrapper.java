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


package org.cougaar.core.security.services.wp;


import java.io.Serializable;

import java.security.SignedObject;
import java.security.cert.X509Certificate;


/**
 * A wrapper interface
 *
 * @author mabrams
 */
public interface Wrapper extends Serializable {
  /**
   * Gets the certificate chain for the signed object
   *
   * @return the <code>X509Certificate</code> chain
   */
  public X509Certificate[] getCertificateChain();


  /**
   * Sets the <code>X509Certificate</code> chain
   *
   * @param certChain - the certificate chain for the signed object
   */
  public void setCertificateChain(X509Certificate[] certChain);


  /**
   * Gets the signed object
   *
   * @return the <code>SignedObject</code>
   */
  public SignedObject getSignedObject();


  /**
   * Sets the signed object for this class
   *
   * @param signedObj
   */
  public void setSignedObject(SignedObject signedObj);
}
