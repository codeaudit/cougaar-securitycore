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

import javax.net.ssl.*;
import java.security.*;
import java.security.cert.*;
import java.net.*;
import java.util.*;

import org.cougaar.core.security.util.*;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.services.crypto.KeyRingService;

public final class UserKeyManager extends org.cougaar.core.security.ssl.KeyManager {
  // provides the default implementation, but it can be overwritten
  private UserCertificateUI userUI;

  // hash map from domain to alias
  private Hashtable domainTable = new Hashtable();
  // hash map from alias to cert
  private Hashtable aliasTable = new Hashtable();

  public UserKeyManager(KeyRingService krs) {
    super(krs);
  }

  public void setUserCertificateUI(UserCertificateUI userUI) {
    this.userUI = userUI;
  }

  public synchronized void updateKeystore() {
    // update domain to alias map table
    domainTable.clear();

    aliasTable.clear();
    KeyStore ks = keyRing.getKeyStore();
    try {
      for (Enumeration e = ks.aliases(); e.hasMoreElements(); ) {
        String alias = (String)e.nextElement();
        aliasTable.put(alias, ks.getCertificate(alias));
      }
    } catch (KeyStoreException ksex) {
      ksex.printStackTrace();
    }
  }

  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    // get the domain and check if there is alias specified for access the domain
    synchronized (this) {
      String alias = null;

      if (socket != null) {
        InetAddress inetaddr = (InetAddress)socket.getInetAddress();
        String host = inetaddr.getHostName();
        // match with the domain list
        alias = (String)domainTable.get(host);
      }

      // if no default alias prompt for user alias
      if (alias == null) {
        alias = userUI.chooseClientAlias(aliasTable);

      }
      return alias;
    }
  }

  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    // user application has no server alias
    return null;
  }

  public X509Certificate[] getCertificateChain(String alias) {
    if (CryptoDebug.debug)
      System.out.println("getCertificateChain: " + alias);

    X509Certificate userx509 = (X509Certificate)aliasTable.get(alias);
    if (userx509 != null) {
      try {
        return keystore.checkCertificateTrust(userx509);
      } catch (Exception e) {
        if (CryptoDebug.debug)
          e.printStackTrace();
      }
    }

    if (CryptoDebug.debug)
      System.out.println("Failed to getCertificateChain");

    return new X509Certificate[] {};
  }

  public String[] getClientAliases(String keyType, Principal[] issuers) {
    // should not just return every user certificate, they should be protected
    // by different passwords
    return new String [] {};
  }

  public PrivateKey getPrivateKey(String alias) {
    if (CryptoDebug.debug)
      System.out.println("getPrivateKey: " + alias);

    PrivateKey privatekey = null;

    // look for it in the
    String commonName = keystore.getCommonName(alias);
    if (commonName != null)
      privatekey = keyRing.findPrivateKey(commonName);

    // prompt for password if user certificate is locked
    // private key not in cert cache, then load it from the keystore
    if (privatekey == null) {
      // prompt until user cancel
      // may setup trial threshold here
      while (true) {
        String pkeypwd = userUI.getUserPassword(alias);
        if (pkeypwd == null) break;

        try {
          privatekey = (PrivateKey)keyRing.getKeyStore().getKey(alias, pkeypwd.toCharArray());
        } catch (Exception ex) {
          if (!(ex instanceof UnrecoverableKeyException))
            break;
        }
      }

      if (privatekey != null) {
        // install into certcache, but does not validate
        // later on the getCertificateChain will be called
        try {
          X509Certificate userx509 = (X509Certificate)
            keyRing.getKeyStore().getCertificate(alias);
          keystore.addCertificateToCache(alias, userx509, privatekey);
        } catch (KeyStoreException ksex) {}
      }
    }
    return privatekey;
  }

  public String[] getServerAliases(String keyType, Principal[] issuers) {
    return new String [] {};
  }


}