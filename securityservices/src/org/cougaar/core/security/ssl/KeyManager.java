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

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.security.util.*;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.services.crypto.*;

public class KeyManager implements X509KeyManager, CertValidityListener {
  protected KeyRingService keyRing = null;
  protected DirectoryKeyStore keystore = null;
  protected String nodealias = null;
  protected X509Certificate nodex509 = null;
  protected String nodename = null;
  private ServiceBroker serviceBroker;
  protected LoggingService log;

  public KeyManager(KeyRingService krs, ServiceBroker sb) {
    keyRing = krs;
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    /*
    // create node cert in advance
    AgentIdentityService ais = (AgentIdentityService)
      serviceBroker.getService(this, AgentIdentityService.class, null);
    try {
      // user application will return null here.
      if (ais != null)
        ais.acquire(null);
    } catch (Exception ex) {
      log.warn("Exception in acquiring identity: " + ex.toString());
    }
    */

    keystore = keyRing.getDirectoryKeyStore();
    if (!(this instanceof UserKeyManager)) {
      keyRing.checkOrMakeCert(getName());
      CertValidityService cvs = (CertValidityService)
        serviceBroker.getService(this,
                                 CertValidityService.class, null);
      cvs.addValidityListener(this);
    }

    // get nodename, nodealias, and node certificate
    updateKeystore();

    if (log.isDebugEnabled())
      log.debug("SSLContext:KeyManager: nodealias is " + nodealias
        + " and nodex509 is " + nodex509);
  }

  public synchronized void updateKeystore() {
    // is the nodeinfo way of retrieving nodename from system property appropriate?
    nodename = getName();

    // get the certificates for the nodename
    // get the last valid certificate
    // use DirectoryKeyStore's functions (it assumes there is only one matching
    // between commonName and cert/alias)
    nodealias = keystore.findAlias(nodename);
    List certList = keyRing.findCert(nodename);
    if (certList != null && certList.size() > 0) {
      nodex509 = ((CertificateStatus)certList.get(0)).getCertificate();
      log.debug("update nodex509: " + nodex509);
    }
  }

  /**  Choose an alias to authenticate the client side of a secure socket
   *   given the public key type and the list of certificate issuer
   *   authorities recognized by the peer (if any).
   */
  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    // node alias if opening socket for RMI... node service
    // if server is tomcat prompt for user certificate
    //if (log.isDebugEnabled())
    //  log.debug("chooseClientAlias: " + socket);
    return nodealias;
  }

  /**
   * Choose an alias to authenticate the server side of a secure socket
   * given the public key type and the list of certificate
   * issuer authorities recognized by the peer (if any).
   */
  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    // if tomcat return tomcat alias
    //if (log.isDebugEnabled())
    //  log.debug("chooseServerAlias: " + nodealias);
    return nodealias;
  }

  /**
   * Returns the certificate chain associated with the given alias.
   */
  public X509Certificate[] getCertificateChain(String alias) {
    // should be only asking for node's chain for now
    if (log.isDebugEnabled())
      log.debug("getCertificateChain: " + alias);

    if (nodex509 != null && alias.equals(nodealias)) {
      try {
        return keystore.checkCertificateTrust(nodex509);
      } catch (Exception e) {
        if (log.isDebugEnabled())
          e.printStackTrace();
      }
    }

    if (log.isDebugEnabled())
      log.debug("Failed to getCertificateChain");

    return new X509Certificate[] {};
  }

  /**
   * Get the matching aliases for authenticating the client side of
   * a secure socket given the public key type and the list of
   * certificate issuer authorities recognized by the peer (if any).
   */
  public String[] getClientAliases(String keyType, Principal[] issuers) {
    // node and agent aliases?
    //if (log.isDebugEnabled())
    //  log.debug("getClientAliases: " + issuers);
    return new String [] {nodealias};
  }

  /**
   * Returns the key associated with the given alias.
   */
  public PrivateKey getPrivateKey(String alias) {
    // only find for node, why would agent certificate be asked?
    if (nodex509 == null || nodealias == null || !alias.equals(nodealias))
      return null;

    if (log.isDebugEnabled())
      log.debug("getPrivateKey: " + alias);

    // DirectoryKeyStore sends out request if key not found
    // Get the first key in the list
    List keylist = keyRing.findPrivateKey(nodename);
    if (keylist == null || keylist.size() == 0)
      return null;

    PrivateKeyCert pkc = (PrivateKeyCert)keylist.get(0);
    return pkc.getPrivateKey();
  }

  /**
   * Returns all aliases of node and agent
   */
  public String[] getServerAliases(String keyType, Principal[] issuers) {
    // node and agent aliases?
    //if (log.isDebugEnabled())
    //  log.debug("getServerAliases: " + issuers);
    return new String [] {nodealias};
  }

  public String getName() {
    return NodeInfo.getNodeName();
  }

  public void updateCertificate() {
    updateKeystore();
  }

}
