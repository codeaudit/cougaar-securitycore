
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

import org.cougaar.core.component.Service;
import org.cougaar.core.security.crypto.CertificateChainException;
import org.cougaar.core.security.crypto.CertificateRevokedException;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.PrivateKeyCert;
import org.cougaar.core.security.naming.CertificateEntry;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.ssl.KeyManager;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.List;

import sun.security.x509.X500Name;

/** Low-level service to retrieve certificates and private keys
 */
public interface KeyRingService extends Service {

  public static final int LOOKUP_LDAP               = 1;
  public static final int LOOKUP_KEYSTORE           = 2;
  public static final int LOOKUP_FORCE_LDAP_REFRESH = 4;

  void setKeyManager(KeyManager km);
  void finishInitialization();

  /**
   * return a private key for the given certificate or null if not found
   */
  PrivateKey findPrivateKey(X509Certificate cert);

   /**
   * @return A list of PrivateKeyCert
   */

  List findPrivateKey(String commonName);
  List findPrivateKey(String commonName, boolean validOnly);
  List findPrivateKey(X500Name x500name);

  /** Get an array of certificates associated with a given entity.
   *  @param principal
   */
  List findCert(Principal p);
  /** Get an array of certificates associated with a given entity.
   *  @param commonName
   */
  List findCert(String commonName);

  List findCert(String commonName, int lookupType);
  List findCert(String commonName, int lookupType, boolean validOnly);
  List findCert(X500Name dname, int lookupType, boolean validOnly);


  Hashtable findCertPairFromNS(String source, String target) throws CertificateException, IOException;
  Hashtable findCertStatusPairFromNS(String source, String target) throws CertificateException, IOException;
  List findDNFromNS(String name) throws IOException;


  List getValidCertificates(X500Name x500Name);
  List getValidPrivateKeys(X500Name x500Name);

  void publishCertificate(CertificateEntry certEntry);
  void updateNS(X500Name x500name);
  void updateNS(String commonName);
  void updateNS(CertificateEntry certEntry)throws Exception;
  // String getCommonName(String alias);

  void removeEntry(String commonName);
  //void addSSLCertificateToCache(X509Certificate cert);
  //void removeEntryFromCache(String commonName);
  void setKeyEntry(PrivateKey key, X509Certificate cert);
  void checkOrMakeCert(String name);
  void checkOrMakeCert(X500Name dname, boolean isCACert);
  void checkOrMakeCert(X500Name dname, boolean isCACert, TrustedCaPolicy trustedCaPolicy);
  boolean checkExpiry(String commonName);

  X509Certificate[] findCertChain(X509Certificate c);
  X509Certificate[] buildCertificateChain(X509Certificate certificate);
  X509Certificate[] checkCertificateTrust(X509Certificate certificate)throws CertificateChainException,
    CertificateExpiredException, CertificateNotYetValidException, CertificateRevokedException ;
  X509Certificate[] checkCertificateTrust(X509Certificate certificate[])
    throws CertificateChainException, CertificateExpiredException, 
    CertificateNotYetValidException, CertificateRevokedException;

  boolean checkCertificate(CertificateStatus cs,
			   boolean buildChain, boolean changeStatus);


  String getAlias(X509Certificate clientX509);
  String findAlias(String commonName);

  byte[] protectPrivateKey(List privKey,
			   List cert,
			   PrivateKey signerPrivKey,
			   X509Certificate signerCert,
			   X509Certificate rcvrCert);

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private key of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  PrivateKeyCert[] getPfx(byte[] pfxBytes,
			  List rcvrPrivKey,
			  List rcvrCert);

  //X509CRL getCRL(String  distingushname);

  List getX500NameFromNameMapping(String name);

  void addToIgnoredList(String cname) throws Exception;

  public KeyManager getClientSSLKeyManager()
    throws IllegalStateException;

}
