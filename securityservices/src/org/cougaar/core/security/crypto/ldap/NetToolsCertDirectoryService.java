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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.Base64;
import org.cougaar.core.security.crypto.CertificateRevocationStatus;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;

public class NetToolsCertDirectoryService
extends CertDirectoryService
implements CertDirectoryServiceClient
{

  public NetToolsCertDirectoryService(CertDirectoryServiceRequestor requestor, ServiceBroker sb) 
    throws javax.naming.NamingException
    {
      super(requestor, sb);
    }

  public LdapEntry getCertificate(SearchResult result) {
    LdapEntry ldapEntry = null;
    X509Certificate certificate = null;
    String pem_cert = null;
    String uniqueIdentifier = null;
    CertificateRevocationStatus status = null;

    // Retrieve attributes for that certificate.
    Attributes attributes = result.getAttributes();
    
    // Check the revocation status of that certificate.
    status = getCertificateRevocationStatus(attributes);

    uniqueIdentifier = getUniqueIdentifier(attributes);

    Attribute x509cert = attributes.get("pem_x509");

    try {
      pem_cert = (String) x509cert.get();
    }
    catch (NamingException e) {
      return null;
    }
    char[] charcert = pem_cert.toCharArray();
    byte[] certdata = Base64.decode(charcert);

    try {
      CertificateFactory certfactory=CertificateFactory.getInstance("X.509");
      InputStream instream=new ByteArrayInputStream(certdata);
      certificate=(X509Certificate)certfactory.generateCertificate(instream);
    }
    catch (Exception exp) {
      log.warn("Unable to get certificate: " + exp);
    }
    if (certificate != null) {
      ldapEntry = new LdapEntry(certificate, uniqueIdentifier, status,CertificateType.CERT_TYPE_END_ENTITY);
    }
    return ldapEntry;
  }

  /** Return the unique identifier of the certificate. */
  private String getUniqueIdentifier(Attributes attributes) {
    Attribute att_uid = attributes.get(UID_ATTRIBUTE);
    String sz_uid = null;
    try {
      sz_uid = (String)att_uid.get();
    }
    catch (NamingException e) {
      if (log.isDebugEnabled()) {
	log.debug("Unable to get unique identifier: " + e);
	e.printStackTrace();
      }
    }
    return sz_uid;
  }

  /** Return the revocation status of the certificate. */
  private CertificateRevocationStatus getCertificateRevocationStatus(Attributes attributes) {
    CertificateRevocationStatus status = null;

    // Retrieve the certificate status
    Attribute att_status = attributes.get(STATUS_ATTRIBUTE);
    String sz_status = null;
    try {
      sz_status = (String)att_status.get();
    }
    catch (NamingException e) {
      if (log.isDebugEnabled()) {
	log.debug("Unable to check revocation status: " + e);
	e.printStackTrace();
      }
      return status;
    }
    if (sz_status != null) {
      int st = Integer.valueOf(sz_status).intValue();
      switch (st) {
      case 1:
	status = CertificateRevocationStatus.VALID;
	break;
      case 3:
	status = CertificateRevocationStatus.REVOKED;
	break;
      default:
	status = CertificateRevocationStatus.UNKNOWN;
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("Certificate status:" + status);
    }
    return status;
  }  

  public X509CRL  getCRL(String  distingushName) {
    return null;
  }
  public String getModifiedTimeStamp(String dn) {
    return null;
  }

}
