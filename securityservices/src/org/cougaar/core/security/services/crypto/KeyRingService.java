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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.Principal;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.*;
import java.security.cert.*;
import sun.security.x509.*;

// Cougaar
import org.cougaar.core.component.Service;

// Cougaar Security Services
import com.nai.security.crypto.*;

/** Low-level service to retrieve certificates
 */
public interface KeyRingService extends Service {

  /** Support for multiple certificates per entity
   */
  X509Certificate[] getCertificates(Principal p);
  PrivateKey[] getPrivateKeys(String commonName);

  /** ******************************
   *  Methods to access public keys
   */

  /** Find the list of all public keys of an entity
   */

  /** 
   */
  Certificate findCert(Principal p);

  /** 
   */
  Certificate findCert(String commonName);

  /**
   */
  Certificate findCert(String commonName, int lookupType);

  /**
   */
  X509Certificate[] findCertChain(X509Certificate c);

  String getCommonName(String alias);

  /** ******************************
   *  Methods to access private keys
   *  Very few selected clients can access this service directly.
   *  These methods are controlled by the security manager.
   */

  /** 
   */
  KeyStore getKeyStore();

  /**
   */
  DirectoryKeyStore getDirectoryKeyStore();

  /** 
   */
  PrivateKey findPrivateKey(String commonName);
  /** 
   */
  PrivateKey findPrivateKey(X500Name x500name);


  Enumeration getAliasList();

  /** ******************************
   *  TODO: Remove these methods
   */
  void checkOrMakeCert(String name);
  void checkOrMakeCert(X500Name dname);
  Vector getCRL();
  long getSleeptime();
  void setSleeptime(long sleeptime);

  void removeEntry(String commonName);
  void setKeyEntry(PrivateKey key, X509Certificate cert);

  byte[] protectPrivateKey(PrivateKey privKey,
				  Certificate cert,
				  PrivateKey signerPrivKey,
				  Certificate signerCert,
				  Certificate rcvrCert);

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private key of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  PrivateKeyCert[] getPfx(byte[] pfxBytes,
				 PrivateKey rcvrPrivKey,
				 Certificate rcvrCert);

  String getAlias(X509Certificate clientX509);
  String parseDN(String aDN);
  X509Certificate[] checkCertificateTrust(X509Certificate certificate)
    throws CertificateChainException, CertificateExpiredException,
    CertificateNotYetValidException, CertificateRevokedException;
}
