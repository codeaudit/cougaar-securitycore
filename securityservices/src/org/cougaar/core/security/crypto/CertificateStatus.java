/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

import org.cougaar.core.security.naming.CertificateEntry;

import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateStatus
  extends CertificateEntry
{
  /** The alias of the entry in the keystore. */
  private String alias = null;

  /** The origin of the certificate (from local keystore,
   *  LDAP certificate directory... */
  private CertificateOrigin certificateOrigin;

  /** The last time a certificate signing request was sent to the
   * certificate authority. */
  private Date lastTimeSigningRequest;

  /** The trust status of this certificate.
   * When a key pair has been generated but not submitted to a CA yet,
   * the certificate cannot be used because other parties will not trust
   * the certificate. */
  private CertificateTrust _certificateTrust;

  public CertificateStatus(X509Certificate cert,
			   CertificateOrigin origin,
			   CertificateRevocationStatus status,
			   CertificateType type,
			   CertificateTrust trust,
			   String a) {
    super(cert, status, type);

    certificateOrigin = origin;
    alias = a;

    // for multiple CA, CA cert cannot be treated as trusted automatically
    setCertificateTrust(trust);
  }

  public String getCertificateAlias() {
    return alias;
  }

  public CertificateOrigin getCertificateOrigin() {
    return certificateOrigin;
  }

  public void setCertificateOrigin(CertificateOrigin origin) {
    certificateOrigin = origin;
  }

  public void setPKCS10Date(Date aDate) {
    lastTimeSigningRequest = aDate;
  }

  public Date getPKCS10Date() {
    return lastTimeSigningRequest;
  }

  // must return the right trust which is passed in from the constructor here
  // CertificateEntry only determines trust by revoke status
  public CertificateTrust getCertificateTrust() {
    return _certificateTrust;
  }

  public void setCertificateTrust(CertificateTrust trust) {
    _certificateTrust = trust;
  }

  public String toString()
  {
    String status = null;
    if (isValid()) {
      status = "Valid";
    }
    else {
      status = "Revoked";
    }
    String alias = getCertificateAlias();
    String theString =
      "DN: " + getCertificate().getSubjectDN().toString();
    if (alias != null || lastTimeSigningRequest != null) {
      theString = theString + "\n     ";
    }
    if (alias != null) {
      theString = theString + "Alias: " + alias + " - ";
    }
    if (lastTimeSigningRequest != null) {
      theString = theString + "PKCS10 sent on " + lastTimeSigningRequest;
    }
    theString = theString +
      "\n     Status: " + status +
      " - Origin: " + getCertificateOrigin() +
      " - Type: " + getCertificateType() +
      " - Trust: " + getCertificateTrust();
    return theString;
  }
}
