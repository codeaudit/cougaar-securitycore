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
import java.util.List;

import org.cougaar.core.security.util.*;
import org.cougaar.core.security.crypto.DirectoryKeyStore;
import org.cougaar.core.security.crypto.PrivateKeyCert;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.services.crypto.KeyRingService;

public class KeyManager implements X509KeyManager {
  protected KeyRingService keyRing = null;
  protected DirectoryKeyStore keystore = null;
  protected String nodealias = null;
  protected X509Certificate nodex509 = null;
  protected String nodename = null;

  public KeyManager(KeyRingService krs) {
    keyRing = krs;
    keystore = keyRing.getDirectoryKeyStore();

    // get nodename, nodealias, and node certificate
    updateKeystore();

    if (CryptoDebug.debug)
      System.out.println("SSLContext:KeyManager: nodealias is " + nodealias
        + " and nodex509 is " + nodex509);
  }

  public synchronized void updateKeystore() {
    // is the nodeinfo way of retrieving nodename from system property appropriate?
    nodename = NodeInfo.getNodeName();

    // get the certificates for the nodename
    // get the last valid certificate
    // use DirectoryKeyStore's functions (it assumes there is only one matching
    // between commonName and cert/alias)
    nodealias = keystore.findAlias(nodename);
    List certList = keyRing.findCert(nodename);
    if (certList.size() > 0) {
      nodex509 = ((CertificateStatus)certList.get(0)).getCertificate();
    }
  }

  /**  Choose an alias to authenticate the client side of a secure socket
   *   given the public key type and the list of certificate issuer
   *   authorities recognized by the peer (if any).
   */
  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    // node alias if opening socket for RMI... node service
    // if server is tomcat prompt for user certificate
    //if (CryptoDebug.debug)
    //  System.out.println("chooseClientAlias: " + socket);
    return nodealias;
  }

  /**
   * Choose an alias to authenticate the server side of a secure socket
   * given the public key type and the list of certificate
   * issuer authorities recognized by the peer (if any).
   */
  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    // if tomcat return tomcat alias
    //if (CryptoDebug.debug)
    //  System.out.println("chooseServerAlias: " + nodealias);
    return nodealias;
  }

  /**
   * Returns the certificate chain associated with the given alias.
   */
  public X509Certificate[] getCertificateChain(String alias) {
    // should be only asking for node's chain for now
    if (CryptoDebug.debug)
      System.out.println("getCertificateChain: " + alias);

    if (nodex509 != null && alias.equals(nodealias)) {
      try {
        return keystore.checkCertificateTrust(nodex509);
      } catch (Exception e) {
        if (CryptoDebug.debug)
          e.printStackTrace();
      }
    }

    if (CryptoDebug.debug)
      System.out.println("Failed to getCertificateChain");

    return new X509Certificate[] {};
  }

  /**
   * Get the matching aliases for authenticating the client side of
   * a secure socket given the public key type and the list of
   * certificate issuer authorities recognized by the peer (if any).
   */
  public String[] getClientAliases(String keyType, Principal[] issuers) {
    // node and agent aliases?
    //if (CryptoDebug.debug)
    //  System.out.println("getClientAliases: " + issuers);
    return new String [] {nodealias};
  }

  /**
   * Returns the key associated with the given alias.
   */
  public PrivateKey getPrivateKey(String alias) {
    // only find for node, why would agent certificate be asked?
    if (nodex509 == null || nodealias == null || !alias.equals(nodealias))
      return null;

    if (CryptoDebug.debug)
      System.out.println("getPrivateKey: " + alias);

    // DirectoryKeyStore sends out request if key not found
    // Get the first key in the list
    PrivateKeyCert pkc = (PrivateKeyCert)keyRing.findPrivateKey(nodename).get(0);
    return pkc.getPrivateKey();
  }

  /**
   * Returns all aliases of node and agent
   */
  public String[] getServerAliases(String keyType, Principal[] issuers) {
    // node and agent aliases?
    //if (CryptoDebug.debug)
    //  System.out.println("getServerAliases: " + issuers);
    return new String [] {nodealias};
  }


}
