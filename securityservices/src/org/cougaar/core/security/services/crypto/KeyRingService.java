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
import org.cougaar.core.security.crypto.*;

/** Low-level service to retrieve certificates and private keys
 */
public interface KeyRingService extends Service {

  /** ******************************
   *  Methods to access public keys
   */

  /** Find the list of all public keys of an entity
   */

  /** Get an array of certificates associated with a given entity.
   *  @param principal
   */
  List findCert(Principal p);

  /**
   */
  List findCert(String commonName);

  public static final int LOOKUP_LDAP               = 1;
  public static final int LOOKUP_KEYSTORE           = 2;
  public static final int LOOKUP_FORCE_LDAP_REFRESH = 4;

  /**
   */
  List findCert(String commonName, int lookupType);
  List findCert(String commonName, int lookupType, boolean validOnly);

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
   * @return A list of PrivateKeyCert
   */
  List findPrivateKey(String commonName);
  List findPrivateKey(String commonName, boolean validOnly);

  /**
   * @return A list of PrivateKeyCert
   */
  List findPrivateKey(X500Name x500name);

  Enumeration getAliasList();

  /** ******************************
   *  TODO: Remove these methods
   */
  void checkOrMakeCert(String name);
  void checkOrMakeCert(X500Name dname);
  void checkOrMakeCert(X500Name dname, boolean isCACert);
  Vector getCRL();
  long getSleeptime();
  void setSleeptime(long sleeptime);

  void removeEntry(String commonName);
  void setKeyEntry(PrivateKey key, X509Certificate cert);

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

  String getAlias(X509Certificate clientX509);
  String parseDN(String aDN);
  X509Certificate[] checkCertificateTrust(X509Certificate certificate)
    throws CertificateChainException, CertificateExpiredException,
    CertificateNotYetValidException, CertificateRevokedException;

  public String getCaKeyStorePath();
  public String getKeyStorePath();

  public boolean checkExpiry(String commonName);
  public void updateNS(String commonName);
}
