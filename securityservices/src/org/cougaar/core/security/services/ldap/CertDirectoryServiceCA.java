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


package org.cougaar.core.security.services.ldap;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

import org.cougaar.core.component.Service;
import org.cougaar.core.security.crypto.CertificateRevocationStatus;

public interface CertDirectoryServiceCA
  extends Service
{

  void publishCertificate(X509Certificate c, int Type,PrivateKey privatekey)
    throws javax.naming.NamingException;

  void publishCRLentry(X509CRLEntry crl);
  /* boolean revokeCertificate(LdapEntry ldapEntry);
  // public boolean revokeCertificate(LdapEntry ldapentry,String CA_DN,LdapEntry ldapentry_ca,PrivateKey privateky, String alg) throws NoSuchAlgorithmException,
                            NoSuchAlgorithmException,
                            InvalidKeyException,
                            NoSuchProviderException,
                            SignatureException;
  */

  SearchResult getLdapentry(String distingushName,boolean uniqueid)
    throws MultipleEntryException, IOException;

  boolean revokeCertificate(String CAbindingName,String userbindingName,
			    PrivateKey caprivatekey, String crlsignalg)
    throws NoSuchAlgorithmException,
    InvalidKeyException,
    CertificateException,
    CRLException,
    NoSuchProviderException,
    SignatureException,
    MultipleEntryException,
    IOException,
    NamingException;

  X509Certificate getCertificate(Attributes attributes)
    throws CertificateException, NamingException;

  boolean isCAEntry(Attributes attributes)
    throws NamingException;

  CertificateRevocationStatus getCertificateRevocationStatus(Attributes attributes);
  String getDirectoryServiceURL();
}
