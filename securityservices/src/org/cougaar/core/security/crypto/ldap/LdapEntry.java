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
package org.cougaar.core.security.crypto.ldap;

import java.security.cert.X509Certificate;
import java.io.Serializable;
import java.security.PublicKey;
import org.cougaar.core.security.crypto.CertificateType;

import org.cougaar.core.security.crypto.CertificateRevocationStatus;

/**
 * A bean which represent a certificate entry in the LDAP server.
 */
public class LdapEntry implements Serializable
{
  private X509Certificate cert;
  private String uniqueIdentifier;
  private CertificateRevocationStatus status;
  private CertificateType type=null;

  public LdapEntry(X509Certificate cert, String id,
		   CertificateRevocationStatus status, CertificateType certtype) 
    {
      this.cert = cert;
      this.uniqueIdentifier = id;
      this.status = status;
      this.type=certtype;
    }
  
  /** 
   * Public accessor method for retrieving the actual certificate.
   */
  public X509Certificate getCertificate() { return cert; }
  
  /**
   * Public accessor method for retrieving the unique hash used for indexing
   * by the LDAP server.
   */
  public String getUniqueIdentifier() { return uniqueIdentifier; }

  /**
   * Public accessor method for retrieving the status of a certificate,
   * where 1 means valid, and  3 means revoked
   */
  public CertificateRevocationStatus getStatus() { return status; }

  /** 
   * Public modifier method for changing the status of this certificate
   * entry in the LDAP server.
   */
  public void setStatus(CertificateRevocationStatus status) {
    this.status = status;
  }
  /**
   * Public accessor method for retrieving the certificate type,
   * certificate can be either CA certificate or entity certificate
   */
  public CertificateType getCertificateType() {
    return type;
  }
  
  public PublicKey getPublicKey() {
    return cert.getPublicKey();
  }
  
  public String getCertDN() {
    String dn=cert.getSubjectDN().getName();
    return dn;
  }

}
