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


package org.cougaar.core.security.crypto;

class CertificateOrigin {
  // enumerator name
  private final String enum_name;
  
  // private constructor, called only within this class
  private CertificateOrigin(String name) {
    enum_name = name;
  }
    
  // return the enumerator name
  public String toString() {
    return enum_name;
  }

  // The certificate is in a local keystore
  public static final CertificateOrigin CERT_ORI_KEYSTORE =
    new CertificateOrigin("ORI_KEYSTORE");

  // The certificate was retrieved from an LDAP directory
  public static final CertificateOrigin CERT_ORI_LDAP =
    new CertificateOrigin("ORI_LDAP");

  // The certificate was received from a Cougaar message (in a PKCS#12
  // envelope).
  public static final CertificateOrigin CERT_ORI_PKCS12 =
    new CertificateOrigin("ORI_PKCS12");
}
