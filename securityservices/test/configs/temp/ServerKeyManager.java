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
package org.cougaar.core.security.ssl;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.util.NodeInfo;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;

public final class ServerKeyManager
  extends org.cougaar.core.security.ssl.KeyManager {
  public ServerKeyManager(KeyRingService krs, ServiceBroker sb)
    throws CertificateException
  {
    super(krs, sb);

//    if (nodex509 == null || nodealias == null) {
    if (fakeAlias == null) {
      log.warn("No valid server certificate");
      throw new CertificateException("No valid server certificate.");
    }
  }

  public synchronized void updateKeystore() {
    super.updateKeystore();

    // no valid certificate? Use self signed cert
    if (nodealias != null && privatekey == null) {
      if (log.isDebugEnabled()) {
        log.debug("No valid server cert, retrieving self sign host cert.");
      }

      CertificateCacheService cacheservice=(CertificateCacheService)
	serviceBroker.getService(this,
				 CertificateCacheService.class,
				 null);
      if(cacheservice==null) {
	log.warn(" Unable to get Certificate Cache service in updateKeystore");
      }
      try {

        nodex509 = null;
	if(cacheservice!=null) {
	  nodex509=cacheservice.getCertificate(nodealias);
          privatekey=cacheservice.getKey(nodealias);
	}
        // No need to get private key, it is not required to
        // start server, only cert and trusted chain are.
        //privatekey = (PrivateKey)keystore.getKeyStore().getKey(nodealias, new char[] {});
        if (nodex509 != null)
          certChain = new X509Certificate [] {nodex509};
      } catch (Exception kex) {
        if (log.isDebugEnabled())
          log.debug("Cannot retrieve server's self-signed cert. " + kex);
      }
    }

    if (log.isDebugEnabled())
      log.debug("WeberserverSSLContext:KeyManager: nodealias is " + nodealias
			 + " and nodex509 is " + nodex509);
  }

  public String chooseClientAlias(String keyType, Principal[] issuers, Socket socket) {
    // server application has no client alias
    return null;
  }

  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    if (nodealias != null)
      return nodealias;
    return fakeAlias;
  }

  public String[] getClientAliases(String keyType, Principal[] issuers) {
    return new String [] {};
  }

  public String[] getServerAliases(String keyType, Principal[] issuers) {
    if (nodealias != null)
      return super.getServerAliases(keyType, issuers);
    return new String [] {fakeAlias};
  }

  public PrivateKey findPrivateKey(String alias) {
    if (nodealias != null) {
      return super.findPrivateKey(alias);
    }
    return fakeKey;
  }

  public X509Certificate [] getCertificateChain(String alias) {
    if (nodealias != null) {
      return super.getCertificateChain(alias);
    }

    return fakeCertChain;
  }

  public String getName() {
    return NodeInfo.getHostName();
  }

  static String fakeAlias = null;
  static X509Certificate [] fakeCertChain;
  static PrivateKey fakeKey = null;
  static Logger _log = LoggerFactory.getInstance().createLogger(KeyManager.class);

  public static void loadFakeKey() throws Exception {
    if (fakeAlias != null) {
      return;
    }

  try {
    String fakeKeystorePath = System.getProperty("javax.net.ssl.keyStore", null);
    String fakeKeypass = System.getProperty("javax.net.ssl.keyStorePassword", null);
    if (fakeKeypass != null && fakeKeystorePath != null) {
      char [] fakePass = fakeKeypass.toCharArray();
      KeyStore store = openKeyStore(fakeKeystorePath, fakePass);
      _log.error("keystore : " + store);
      for (Enumeration en = store.aliases(); en.hasMoreElements(); ) {
        fakeAlias = (String)en.nextElement();
        _log.error("alias : " + fakeAlias);
        break;
      }
      if (fakeAlias != null) {
        X509Certificate cert = (X509Certificate)store.getCertificate(fakeAlias);
        fakeCertChain = new X509Certificate[] {cert};
        fakeKey = (PrivateKey)store.getKey(fakeAlias, fakePass);
        if (fakeCertChain != null && fakeCertChain.length != 0)
          _log.error("chain: " + fakeCertChain[0]);
        _log.error("key: " + fakeKey);
      }
    }

  } catch (Exception ex) {
    _log.error("Error in getting fake key: ", ex);
    throw ex;
  }
  }

  static KeyStore openKeyStore(String keystorePath, char [] storePass) throws Exception {
        KeyStore k = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream fos = new FileInputStream(keystorePath);
        k.load(fos, storePass);
        fos.close();
        return k;
  }
}
