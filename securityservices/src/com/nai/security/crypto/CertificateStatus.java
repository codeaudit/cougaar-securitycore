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
import java.util.Date;

public class CertificateStatus
{
  private boolean debug = false;

  /** Creates new CertificateStatus */
  private java.security.cert.Certificate certificate = null;

  /** true: certificate has not been revoked.
   * false: certificate has been revoked */
  private boolean certificateIsValid = true;

  /** The alias of the entry in the keystore. */
  private String alias = null;

  /** The origin of the certificate (from local keystore,
   *  LDAP certificate directory... */
  private CertificateOrigin certificateOrigin;

  /** The type of the certificate: end entity or trusted certificate
      authority */
  private CertificateType certificateType;
  
  /** The last time a certificate signing request was sent to the
   * certificate authority. */
  private Date lastTimeSigningRequest;

  /** The trust status of this certificate.
   * When a key pair has been generated but not submitted to a CA yet,
   * the certificate cannot be used because other parties will not trust
   * the certificate. */
  private CertificateTrust certificateTrust;
  
  public CertificateStatus(java.security.cert.Certificate cert,
			   boolean isValid,
			   CertificateOrigin origin, CertificateType type,
			   CertificateTrust trust,
			   String a) {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();

    certificate = cert;
    certificateIsValid = isValid;
    certificateOrigin = origin;
    certificateType = type;
    alias = a;
    if (type == CertificateType.CERT_TYPE_CA) {
      // The certificate is necessarily trusted, regardless
      // of the trust parameter.
      certificateTrust = CertificateTrust.CERT_TRUST_CA_CERT;
    }
    else {
      certificateTrust = trust;
    }
  }

  /** Return true if the certificate is valid */
  public void checkCertificateValidity()
    throws CertificateExpiredException, CertificateNotYetValidException,
	   CertificateRevokedException, CertificateNotTrustedException
  {
    if (debug) {
      System.out.println("Checking certificate validity for "
			 + ((X509Certificate) getCertificate()).getSubjectDN());
    }

    if (getCertificateTrust() == CertificateTrust.CERT_TRUST_CA_SIGNED ||
	getCertificateTrust() == CertificateTrust.CERT_TRUST_CA_CERT) {
      // The certificate is trusted. Check revocation, expiration date
      // and "not before" date.
      if (isValid()) {
	X509Certificate c = (X509Certificate) getCertificate();
	c.checkValidity();
	// 1- Certificate can be used now ("not before" date is not in the future)
	// 2- Certificate has not expired ("not after" date is not in the past)
      }
      else {
	if (debug) {
	  System.out.println("Certificate has been revoked");
	}
	throw new CertificateRevokedException("Certificate has been revoked");
      }
    }
    else {
      if (debug) {
	System.out.println("Certificate not trusted: " + getCertificateTrust());
      }
      throw new CertificateNotTrustedException("Certificate not trusted:",
					       getCertificateTrust());
    }
  }

  public java.security.cert.Certificate getCertificate() {
    return certificate;
  }

  public boolean isValid() {
    return certificateIsValid;
  }

  public String getCertificateAlias() {
    return alias;
  }

  public CertificateOrigin getCertificateOrigin() {
    return certificateOrigin;
  }

  public CertificateType getCertificateType() {
    return certificateType;
  }

  public CertificateTrust getCertificateTrust() {
    return certificateTrust;
  }

  public void setCertificateTrust(CertificateTrust trust) {
    certificateTrust = trust;
  }

  public void setCertificate(Certificate c) {
    certificate = c;
  }

  public void setPKCS10Date(Date aDate) {
    lastTimeSigningRequest = aDate;
  }

  public Date getPKCS10Date() {
    return lastTimeSigningRequest;
  }

  public String toString()
  {
    String status = null;
    if (isValid()) {
      status = "Not revoked";
    }
    else {
      status = "Revoked";
    }
    String alias = getCertificateAlias();
    String theString =
      "DN: " + ((X509Certificate) certificate).getSubjectDN().toString();
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
