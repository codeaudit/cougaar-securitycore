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
import java.util.Vector;

// Cougaar
import org.cougaar.core.component.Service;

// Cougaar Security Services
import com.nai.security.crypto.PrivateKeyCert;

/** Low-level service to retrieve certificates
 */
public interface KeyRingService extends Service {

  /** ******************************
   *  Methods to access public keys
   */

  /** 
   */
  public Certificate findCert(Principal p);

  /** 
   */
  public Certificate findCert(String commonName);

  /**
   */
  public Certificate findCert(String commonName, int lookupType);

  /**
   */
  public X509Certificate[] findCertChain(X509Certificate c);


  /** ******************************
   *  Methods to access private keys
   *  Very few selected clients can access this service directly.
   *  These methods are controlled by the security manager.
   */

  /** 
   */
  public KeyStore getKeyStore();

  /** 
   */
  public PrivateKey findPrivateKey(String commonName);


  /** ******************************
   *  TODO: Remove these methods
   */
  public void checkOrMakeCert(String name);
  public Vector getCRL();
  public long getSleeptime();
  public void setSleeptime(long sleeptime);

  public byte[] protectPrivateKey(PrivateKey privKey,
				  Certificate cert,
				  PrivateKey signerPrivKey,
				  Certificate signerCert,
				  Certificate rcvrCert);

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private key of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  public PrivateKeyCert[] getPfx(byte[] pfxBytes,
				 PrivateKey rcvrPrivKey,
				 Certificate rcvrCert);


}
