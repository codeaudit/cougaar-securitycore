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

import java.security.SignedObject;
import java.security.cert.X509Certificate;


/**
 * A wrapped request object containing the a signed request object with its
 * certificate chain
 *
 * @author mabrams
 */
public class ProtectedRequest implements org.cougaar.core.service.wp.WhitePagesProtectionService.Wrapper {
  private X509Certificate[] certificateChain = null;
  private SignedObject signedObject = null;

  /**
   * Creates a new ProtectedRequest object.
   *
   * @param chain the certificate chain
   * @param signed the signed object
   */
  public ProtectedRequest(X509Certificate[] chain, SignedObject signed) {
    this.certificateChain = chain;
    this.signedObject = signed;
  }

  /**
   * @see org.cougaar.core.security.services.wp.Wrapper#getSignedObject()
   */
  public SignedObject getSignedObject() {
    return signedObject;
  }


  /**
   * @see org.cougaar.core.security.services.wp.Wrapper#setSignedObject()
   */
  public void setSignedObject(SignedObject signedObj) {
    this.signedObject = signedObj;
  }


  /**
   * @see org.cougaar.core.security.services.wp.Wrapper#getCertificateChain()
   */
  public X509Certificate[] getCertificateChain() {
    return certificateChain;
  }


  /**
   * @see org.cougaar.core.security.services.wp.Wrapper#setCertificateChain(java.security.cert.X509Certificate[])
   */
  public void setCertificateChain(X509Certificate[] certChain) {
    this.certificateChain = certChain;
  }
}
