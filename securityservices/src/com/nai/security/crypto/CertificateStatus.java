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
 *
 * Created on September 12, 2001, 10:55 AM
 */

/**
 *
 * @author  rtripath
 * @version 
 */

package com.nai.security.crypto;

import java.security.cert.*;
public class CertificateStatus
{

  /** Creates new CertificateStatus */
  private java.security.cert.Certificate certificate = null;
  private boolean isValid = true;
  private int certificateOrigin;
  
  /** Possible values for certificateOrigin */
  public static final int CERT_KEYSTORE = 1;
  public static final int CERT_LDAP = 2;

  public CertificateStatus(java.security.cert.Certificate cert, boolean status, int origin) {
    certificate = cert;
    isValid = status;
  }

  /*
  public CertificateStatus(Certificate cert) {
    certificate = cert;
  }
  */

  public java.security.cert.Certificate getCertificate() {
    return certificate;
  }

  public boolean isValid() {
    return isValid;
  }

  public int getCertificateOrigin() {
    return certificateOrigin;
  }
}
