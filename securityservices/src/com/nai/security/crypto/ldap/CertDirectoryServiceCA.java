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
 */

package com.nai.security.crypto.ldap;

import java.util.*;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRLEntry;
import com.nai.security.crypto.ldap.LdapEntry;
import java.security.*;
import java.io.IOException;
import javax.naming.NamingException;
import javax.naming.directory.SearchResult;
import javax.naming.directory.Attributes;
import com.nai.security.crypto.MultipleEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CRLException;


public interface CertDirectoryServiceCA {

  void publishCertificate(X509Certificate c, int Type,PrivateKey privatekey);
  void publishCRLentry(X509CRLEntry crl);
  /* boolean revokeCertificate(LdapEntry ldapEntry);
  // public boolean revokeCertificate(LdapEntry ldapentry,String CA_DN,LdapEntry ldapentry_ca,PrivateKey privateky, String alg) throws NoSuchAlgorithmException,
                            NoSuchAlgorithmException,
                            InvalidKeyException,
                            NoSuchProviderException,
                            SignatureException;
  */
   public SearchResult getLdapentry(String distingushName,boolean uniqueid) throws MultipleEntryException, IOException  ;
  public boolean revokeCertificate(String CAbindingName,String userbindingName,PrivateKey caprivatekey, String crlsignalg) throws NoSuchAlgorithmException,
                            InvalidKeyException,
			    CertificateException,
			    CRLException,
                            NoSuchProviderException,
                            SignatureException,
                            MultipleEntryException,
			    IOException,
			    NamingException;
  public  X509Certificate getCertificate(Attributes attributes) throws CertificateException, NamingException;
  public  boolean isCAEntry(Attributes attributes)throws NamingException;

}
