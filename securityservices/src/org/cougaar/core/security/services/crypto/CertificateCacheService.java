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

package org.cougaar.core.security.services.crypto;

import java.lang.*;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.Principal;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.*;
import java.security.cert.*;
import sun.security.x509.*;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyStoreException;

// Cougaar
import org.cougaar.core.component.Service;

// Cougaar Security Services
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.ssl.*;

/** Low-level service to update and retrive certificates and private keys from the Certificate Cache 
 */
public interface CertificateCacheService extends Service {

  Enumeration getAliasList();
  KeyStore getKeyStore();
  List getX500NameFromNameMapping(String cougaarName);
  // boolean  presentInNameMapping(String commonName);
  List getCertificates(X500Name x500Name);
  CertificateStatus addCertificate(CertificateStatus certEntry);
  void addNameToNameMapping(CertificateStatus certStatus);
  void addCertificateToCache(String alias,
			     X509Certificate importCert,
			     PrivateKey privatekey);
  void removeEntryFromCache(String commonName);
  void addSSLCertificateToCache(X509Certificate cert);
  void addPrivateKey(PrivateKey privatekey, CertificateStatus certEntry);
  String findAlias(X500Name adname);
  //void removeEntry(String commonName);
  //void setKeyEntry(PrivateKey key, X509Certificate cert);
  boolean  presentInNameMapping(X500Name dname) ;
  //List getValidPrivateKeys(X500Name x500Name);
  List getPrivateKeys(X500Name x500Name);
  PrivateKey getKey(String alias, char[] pwd) throws KeyStoreException,
                        NoSuchAlgorithmException,
    UnrecoverableKeyException;
  String getCommonName(String alias);
  String getCommonName(X500Name x500Name) ;
  String getCommonName(X509Certificate x509); 
  //List getValidCertificates(X500Name x500Name);
  X509Certificate getCertificate(String alias)throws KeyStoreException;
  PrivateKey getKey(String alias) throws KeyStoreException,
                        NoSuchAlgorithmException,
                        UnrecoverableKeyException;
  void setKeyEntry(String alias, PrivateKey privatekey,
		    X509Certificate[] certificate);
  void setKeyEntry(String alias, PrivateKey privatekey, char[] pwd,
			  Certificate[] certificate) throws KeyStoreException;

  void saveCertificateInTrustedKeyStore(X509Certificate aCertificate,
					String alias);
  X509Certificate[] getTrustedIssuers();
  void deleteEntry(String alias, String commonName);
  void printCertificateCache();
  CertificateStatus addKeyToCache(X509Certificate certificate, PrivateKey key,
				  String alias, CertificateType certType);
  
  boolean setCertificateTrust(X509Certificate certificate, CertificateStatus cs,
			      X500Name name, Hashtable selfsignedCAs);
  Certificate[] getCertificateChain(String alias)throws KeyStoreException ;
  Enumeration getKeysInCache();
  void revokeStatus(BigInteger serialno, String issuerDN, String subjectDN);
  String getDN(CRLKey crlkey);
  String getKeyStorePath();
  String getCaKeyStorePath();
  void updateBigInt2Dn(X509Certificate cert, boolean actionIsPut) ;
  boolean checkRevokedCache(X509Certificate certificate);
  void addToRevokedCache(String issuerDN, BigInteger serialno) ;
  void addTrustListener(TrustManager tm);
}
