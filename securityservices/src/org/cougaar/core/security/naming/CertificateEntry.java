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

package org.cougaar.core.security.naming;

import java.util.*;
import java.security.cert.*;
import sun.security.x509.*;
import java.io.Serializable;

import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.crypto.ldap.*;

public class CertificateEntry
  implements Serializable
{
  private X509Certificate cert;
  private X509Certificate [] certChain;
  private String uniqueIdentifier;
  private CertificateRevocationStatus status;
  private CertificateType type=null;

  public CertificateEntry(X509Certificate cert, String id,
		   CertificateRevocationStatus status, CertificateType certtype)
  {
    this.cert = cert;
    this.uniqueIdentifier = id;
    this.status = status;
    this.type=certtype;
    certChain = new X509Certificate [] {cert};
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

  public X509Certificate [] getCertificateChain() {
    return certChain;
  }

  public void setCertificateChain(X509Certificate [] certs) {
    certChain = certs;
  }

  public CertificateTrust getCertificateTrust() {
    CertificateTrust certTrust = CertificateTrust.CERT_TRUST_UNKNOWN;
    if(getStatus().equals(CertificateRevocationStatus.REVOKED)) {
      certTrust = CertificateTrust.CERT_TRUST_REVOKED_CERT;
    }
    if(getStatus().equals(CertificateRevocationStatus.VALID)) {
      certTrust = CertificateTrust.CERT_TRUST_CA_SIGNED;
    }
    return certTrust;
  }
}