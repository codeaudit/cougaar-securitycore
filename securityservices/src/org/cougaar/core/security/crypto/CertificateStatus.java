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

import java.security.cert.*;
import java.util.Date;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;

public class CertificateStatus
{
  //private boolean debug = false;

  /** Creates new CertificateStatus */
  private X509Certificate certificate = null;

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
  private ServiceBroker serviceBroker;
  private LoggingService log;
  private CertDirectoryServiceClient certFinder;

  public CertificateStatus(X509Certificate cert,
			   boolean isValid,
			   CertificateOrigin origin, CertificateType type,
			   CertificateTrust trust,
			   String a,
			   ServiceBroker sb) {
    if (cert == null) {
      throw new IllegalArgumentException("Null certificate");
    }

    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    certificate = cert;
    certificateIsValid = isValid;
    certificateOrigin = origin;
    certificateType = type;
    alias = a;
    /*
    if (type == CertificateType.CERT_TYPE_CA) {
      // The certificate is necessarily trusted, regardless
      // of the trust parameter.
      certificateTrust = CertificateTrust.CERT_TRUST_CA_CERT;
    }
    else {
      certificateTrust = trust;
    }
    */
    // for multiple CA, CA cert cannot be treated as trusted automatically
    certificateTrust = trust;
  }

  /** Return true if the certificate is valid */
  public void checkCertificateValidity()
    throws CertificateExpiredException, CertificateNotYetValidException,
	   CertificateRevokedException, CertificateNotTrustedException
  {
    if (log.isDebugEnabled()) {
      log.debug("Checking certificate validity for "
			 + ((X509Certificate) getCertificate()).getSubjectDN());
    }

    if (getCertificateTrust() == CertificateTrust.CERT_TRUST_CA_SIGNED ||
	getCertificateTrust() == CertificateTrust.CERT_TRUST_CA_CERT) {
      // The certificate is trusted. Check revocation, expiration date
      // and "not before" date.
      if (isValid()) {
	X509Certificate c = getCertificate();
	c.checkValidity();
	// 1- Certificate can be used now ("not before" date is not in the future)
	// 2- Certificate has not expired ("not after" date is not in the past)
      }
      else {
	if (log.isDebugEnabled()) {
	  log.debug("Certificate has been revoked");
	}
	throw new CertificateRevokedException("Certificate has been revoked");
      }
    }
    else {
      if (log.isDebugEnabled()) {
	log.debug("Certificate not trusted: " + getCertificateTrust());
      }
      if(getCertificateTrust() == CertificateTrust. CERT_TRUST_REVOKED_CERT) {
	certificateIsValid=false;
	throw new CertificateRevokedException("Certificate not trusted:"+
      				       getCertificateTrust());
      }
      else {
	throw new CertificateNotTrustedException("Certificate not trusted:",
      				       getCertificateTrust());
	  }
    }
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  public boolean isValid() {
    return certificateIsValid;
  }

   public void  setValidity(boolean valid) {
     certificateIsValid=valid;
     //return certificateIsValid;
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
  
  public void setCertificateOrigin(CertificateOrigin origin) {
    certificateOrigin = origin;
  }

  public void setCertificateTrust(CertificateTrust trust) {
    if (log.isDebugEnabled()) {
      String msg = "Set certificate trust:" + trust + " for ";
      if (certificate != null) {
	msg = msg + ((X509Certificate) certificate).getSubjectDN().toString();
      }
      else {
	msg = msg + "unknown";
      }
      log.debug(msg);
    }

    certificateTrust = trust;
  }

  public void setCertificateType(CertificateType type) {
    if (log.isDebugEnabled()) {
      String msg = "Set certificate type:" + type + " for ";
      if (certificate != null) {
	msg = msg + ((X509Certificate) certificate).getSubjectDN().toString();
      }
      else {
	msg = msg + "unknown";
      }
      log.debug(msg);
    }
    certificateType = type;
  }

  public void setCertificate(X509Certificate c) {
    certificate = c;
  }

  public void setPKCS10Date(Date aDate) {
    lastTimeSigningRequest = aDate;
  }

  public Date getPKCS10Date() {
    return lastTimeSigningRequest;
  }

  public void setCertFinder(CertDirectoryServiceClient certFinder) {
    this.certFinder = certFinder;
  }

  public CertDirectoryServiceClient getCertFinder() {
    return certFinder;
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
