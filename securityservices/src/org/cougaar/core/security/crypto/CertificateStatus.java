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
