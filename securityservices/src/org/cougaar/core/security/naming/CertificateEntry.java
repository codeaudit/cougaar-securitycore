/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.naming;

import org.cougaar.core.security.crypto.CertificateNotTrustedException;
import org.cougaar.core.security.crypto.CertificateRevocationStatus;
import org.cougaar.core.security.crypto.CertificateRevokedException;
import org.cougaar.core.security.crypto.CertificateTrust;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.crypto.CertificateUtility;

import java.io.Serializable;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

public class CertificateEntry
  implements Serializable
{
  /** The X.509 certificate */
  private X509Certificate _certificate;

  /** The X.509 certificate chain */
  private X509Certificate [] _certificateChain;

  /* A unique identifier for the certificate */
  private String _uniqueIdentifier;

  /** The status of the certificate: valid, revoked, or unknown
   */
  private CertificateRevocationStatus _certificateStatus;

  /** The type of the certificate: end entity or trusted certificate
      authority */
  private CertificateType _certificateType=null;

  public CertificateEntry(X509Certificate cert,
			  CertificateRevocationStatus status,
			  CertificateType certtype)
  {
    if (cert == null) {
      throw new IllegalArgumentException("Null certificate");
    }

    _certificate = cert;
    _uniqueIdentifier = CertificateUtility.getUniqueIdentifier(cert);
    _certificateStatus = status;
    _certificateType = certtype;
    _certificateChain = new X509Certificate [] {cert};
  }

  /**
   * Public accessor method for retrieving the actual certificate.
   */
  public X509Certificate getCertificate() { return _certificate; }

  /**
   * Set the certificate
   */
  public void setCertificate(X509Certificate c) {
    _certificate = c;
  }

  /**
   * Public accessor method for retrieving the unique hash used for indexing
   * by the LDAP server.
   */
  public String getUniqueIdentifier() { return _uniqueIdentifier; }

  /**
   * Public accessor method for retrieving the status of a certificate,
   * where 1 means valid, and  3 means revoked
   */
  public CertificateRevocationStatus getCertificateRevocationStatus() {
    return _certificateStatus;
  }
  public void setCertificateRevocationStatus(CertificateRevocationStatus status) {
    _certificateStatus = status;
  }

  public boolean isValid() {
    if (getCertificateRevocationStatus().equals(CertificateRevocationStatus.VALID)) {
      return true;
    }
    else {
      return false;
    }
  }

  /**
   * Public modifier method for changing the status of this certificate
   * entry in the LDAP server.
   */
  public void setStatus(CertificateRevocationStatus status) {
    _certificateStatus = status;
  }
   /**
   * Public accessor method for retrieving the certificate type,
   * certificate can be either CA certificate or entity certificate
   */
  public CertificateType getCertificateType() {
    return _certificateType;
  }
  public void setCertificateType(CertificateType type) {
    _certificateType = type;
  }

  public X509Certificate [] getCertificateChain() {
    return _certificateChain;
  }

  public void setCertificateChain(X509Certificate [] certs) {
    _certificateChain = certs;
  }

  public CertificateTrust getCertificateTrust() {
    CertificateTrust certTrust = CertificateTrust.CERT_TRUST_UNKNOWN;
    if(getCertificateRevocationStatus().equals(CertificateRevocationStatus.REVOKED)) {
      certTrust = CertificateTrust.CERT_TRUST_REVOKED_CERT;
    }
    if(getCertificateRevocationStatus().equals(CertificateRevocationStatus.VALID)) {
      certTrust = CertificateTrust.CERT_TRUST_CA_SIGNED;
    }
    return certTrust;
  }


  /** Check the validity of the certificate.
   */
  public void checkCertificateValidity()
    throws CertificateExpiredException,
    CertificateNotYetValidException,
    CertificateRevokedException,
    CertificateNotTrustedException
  {
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
	throw new CertificateRevokedException("Certificate has been revoked");
      }
    }
    else {
      if(getCertificateTrust() == CertificateTrust. CERT_TRUST_REVOKED_CERT) {
	//certificateIsValid=false;
	throw new CertificateRevokedException("Certificate not trusted:"+
      				       getCertificateTrust());
      }
      else {
	throw new CertificateNotTrustedException("Certificate not trusted:",
      				       getCertificateTrust());
      }
    }
  }

  public String toString() {
    return "uid " + _uniqueIdentifier + ", type " + _certificateType + ", status " + _certificateStatus;
  }
}
