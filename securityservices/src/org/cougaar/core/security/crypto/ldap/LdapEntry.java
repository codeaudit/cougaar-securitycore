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

package org.cougaar.core.security.crypto.ldap;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.cougaar.core.security.crypto.CertificateRevocationStatus;
import org.cougaar.core.security.crypto.CertificateType;

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
