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
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.userauth.AuthenticationHandler;
import org.cougaar.core.security.userauth.CertAuthListener;

import java.net.PasswordAuthentication;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public final class UserKeyManager extends org.cougaar.core.security.ssl.KeyManager
  implements CertAuthListener
{
  // provides the default implementation, but it can be overwritten
  private AuthenticationHandler handler;

  /*
  // hash map from domain to alias
  private Hashtable domainTable;
  // hash map from alias to cert
  private Hashtable aliasTable;
  */

  protected X509Certificate userx509 = null;

  public UserKeyManager(KeyRingService krs, ServiceBroker sb) {
    super(krs, sb);
  }

  public void setPasswordAuthentication(PasswordAuthentication pa) {}

  public void setAuthHandler(AuthenticationHandler auth) {
    this.handler = auth;
    auth.setAuthListener(this);
  }

  public void setAlias(String alias) {
    nodealias = alias;
  }

  public void setPrivateKey(PrivateKey pkey) {
    privatekey = pkey;
  }

  public void setCertificate(X509Certificate cert) {
    userx509 = cert;
  }

  public synchronized void updateKeystore() {
  /*
    if (domainTable == null) {
      domainTable = new Hashtable();
      aliasTable = new Hashtable();
    }

    // update domain to alias map table
    domainTable.clear();
    aliasTable.clear();
    KeyStore ks = keyRing.getKeyStore();
    try {
      for (Enumeration e = ks.aliases(); e.hasMoreElements(); ) {
        String alias = (String)e.nextElement();
        X509Certificate usrcert = (X509Certificate)
          ks.getCertificate(alias);
        String attrib = usrcert.getSubjectDN().getName();
        if (!CertificateUtility.findAttribute(attrib, "t").equals(
          DirectoryKeyStore.CERT_TITLE_USER))
          continue;
        aliasTable.put(alias, usrcert);
      }
    } catch (KeyStoreException ksex) {
      ksex.printStackTrace();
    }
    */
  }

  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    /*
    // get the domain and check if there is alias specified for access the domain
    synchronized (this) {
      String alias = null;

      if (socket != null) {
        InetAddress inetaddr = (InetAddress)socket.getInetAddress();
        String host = inetaddr.getHostName();
        if (log.isDebugEnabled())
          log.debug("Connecting to host: " + host);

        // match with the domain list
        alias = (String)domainTable.get(host);
      }

      // if no default alias prompt for user alias
      if (alias == null) {
        if (aliasTable.size() > 0)
          alias = userUI.chooseClientAlias(aliasTable);

      }
      return alias;
    }
    */
    if (nodealias == null && handler != null) {
      try {
        handler.authenticateUser(handler.getUserName());
      } catch (Exception ex) {}
    }

    return nodealias;
  }

  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    // user application has no server alias
    return null;
  }

  public X509Certificate[] getCertificateChain(String alias) {
    if (log.isDebugEnabled())
      log.debug("getCertificateChain: " + alias);

    //X509Certificate userx509 = (X509Certificate)aliasTable.get(alias);
    if (alias.equals(nodealias) && userx509 != null) {
      try {
        return keyRing.checkCertificateTrust(userx509);
      } catch (Exception e) {
        if (log.isWarnEnabled()) {
	  log.warn("Failed to check certificate trust of user certificate");
	}
      }
    }

    if (log.isWarnEnabled())
      log.warn("Failed to getCertificateChain");

    return new X509Certificate[] {};
  }

  public String[] getClientAliases(String keyType, Principal[] issuers) {
    // should not just return every user certificate, they should be protected
    // by different passwords
    return new String [] {};
  }

  public PrivateKey getPrivateKey(String alias) {
    if (log.isDebugEnabled())
      log.debug("getPrivateKey: " + alias);

      /*
    PrivateKey privatekey = null;

    // look for it in the
    String commonName = keystore.getCommonName(alias);
    if (commonName != null) {
      List privatekeyList = keyRing.findPrivateKey(commonName);
      privatekey = ((PrivateKeyCert)privatekeyList.get(0)).getPrivateKey();
    }

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
    */
    return privatekey;
  }

  public String[] getServerAliases(String keyType, Principal[] issuers) {
    return new String [] {};
  }


}
