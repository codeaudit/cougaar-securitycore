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
import org.cougaar.core.security.crypto.CertValidityListener;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.PrivateKeyCert;
import org.cougaar.core.security.services.crypto.CertValidityService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.service.LoggingService;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.X509KeyManager;

public class KeyManager implements X509KeyManager, CertValidityListener {
  protected KeyRingService keyRing = null;
 
  protected String nodealias = null;
  protected PrivateKey privatekey = null;
  protected X509Certificate [] certChain = null;
  protected X509Certificate nodex509 = null;
  protected String nodename = null;
  protected ServiceBroker serviceBroker;
  protected LoggingService log;
  private boolean warningLogged = false;

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

    if (keyRing == null) {
      log.warn("KeyRing service is not available. Unable to initialize the KeyManager.");
      throw new RuntimeException("KeyRing service is not available");
    }

    // keystore = keyRing.getDirectoryKeyStore();
    keyRing.setKeyManager(this);
  }

  public synchronized void finishInitialization() {
    if (!(this instanceof UserKeyManager)) {
      keyRing.checkOrMakeCert(getName());
      CertValidityService cvs = (CertValidityService)
        serviceBroker.getService(this,
                                 CertValidityService.class, null);
      cvs.addValidityListener(this);
      cvs.addInvalidateListener(this);
    }

    updateKeystore();
  }

  public synchronized void updateKeystore() {
    // is the nodeinfo way of retrieving nodename from system property appropriate?
    nodename = getName();

    // get the certificates for the nodename
    // get the last valid certificate
    // use DirectoryKeyStore's functions (it assumes there is only one matching
    // between commonName and cert/alias)
    
    if(keyRing!=null) {
      nodealias =  keyRing.findAlias(nodename);
    }
    if (log.isDebugEnabled()) {
      log.debug("updateKeystore - Node name: " + nodename +
		" - Node alias: " + nodealias);
    }
    if(nodealias==null) {
      if (privatekey != null) {
        log.warn("No longer have valid certificate.");
      }

      return;
    }
    List certList = keyRing.findCert(nodename, KeyRingService.LOOKUP_KEYSTORE);
    if (certList != null && certList.size() > 0) {
      nodex509 = ((CertificateStatus)certList.get(0)).getCertificate();
      if (log.isDebugEnabled()) {
        log.debug("update nodex509: " + nodex509);
      }

      privatekey = findPrivateKey(nodealias);
      certChain = findCertificateChain(nodealias);
      if (privatekey != null) {
        setManagerReady();
      }
    }

    if (log.isInfoEnabled()) {
      String s = "SSLContext:KeyManager: node name: " + nodename
	+ " - nodealias is " + nodealias
	+ " and nodex509 is " + nodex509 + " - cert Chain: ";
      if (certChain != null) {
	s = s + certChain[0];
      }
      log.info(s);
    }
  }

  /**  Choose an alias to authenticate the client side of a secure socket
   *   given the public key type and the list of certificate issuer
   *   authorities recognized by the peer (if any).
   */
  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    // node alias if opening socket for RMI... node service
    // if server is tomcat prompt for user certificate
    if (log.isDebugEnabled())
      log.debug("chooseClientAlias: " + socket);
    return nodealias;
  }

  /**
   * Choose an alias to authenticate the server side of a secure socket
   * given the public key type and the list of certificate
   * issuer authorities recognized by the peer (if any).
   */
  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    // if tomcat return tomcat alias
    if (log.isDebugEnabled())
      log.debug("chooseServerAlias: " + nodealias);
    return nodealias;
  }

  /**
   * Returns the certificate chain associated with the given alias.
   */
  public X509Certificate[] getCertificateChain(String alias) {
    if (log.isDebugEnabled()) {
      log.debug("getCertificateChain: " + SSLDebug.getCertsDnNames(certChain));
    }
    return certChain;
  }

  protected X509Certificate[] findCertificateChain(String alias) {
    // should be only asking for node's chain for now
    if (log.isDebugEnabled()) {
      log.debug("getCertificateChain: " + alias);
    }

    if (nodex509 != null && alias.equals(nodealias)) {
      try {
	if(keyRing!=null){
	  return keyRing.checkCertificateTrust(nodex509);
	}
      } catch (Exception e) {
        if (log.isWarnEnabled()) {
	  log.warn("Unable to get certificate chain for "
		   + alias + ": " + e);
	}
      }
    }

    if (log.isWarnEnabled()) {
      log.warn("Failed to getCertificateChain for " + alias);
    }
    return new X509Certificate[] {};
  }

  /**
   * Get the matching aliases for authenticating the client side of
   * a secure socket given the public key type and the list of
   * certificate issuer authorities recognized by the peer (if any).
   */
  public String[] getClientAliases(String keyType, Principal[] issuers) {
    // node and agent aliases?
    if (log.isDebugEnabled())
      log.debug("getClientAliases: " + issuers);
    return new String [] {nodealias};
  }

  /**
   * Returns the key associated with the given alias.
   */
  public PrivateKey getPrivateKey(String alias) {
    return privatekey;
  }

  protected PrivateKey findPrivateKey(String alias) {
    // only find for node, why would agent certificate be asked?
    if (nodex509 == null || nodealias == null || !alias.equals(nodealias))
      return null;

    if (log.isDebugEnabled()) {
      log.debug("getPrivateKey: " + alias);
    }

    // DirectoryKeyStore sends out request if key not found
    // Get the first key in the list
    List keylist = keyRing.findPrivateKey(nodename);
    if (keylist == null || keylist.size() == 0) {
      if (!warningLogged) {
	log.warn("No private key available for " + alias);
	warningLogged = true;
      }
      return null;
    }

    PrivateKeyCert pkc = (PrivateKeyCert)keylist.get(0);
    if (pkc == null) {
      log.error("Could not find private key for " + alias);
    }
    return pkc.getPrivateKey();
  }

  /**
   * Returns all aliases of node and agent
   */
  public String[] getServerAliases(String keyType, Principal[] issuers) {
    // node and agent aliases?
    if (log.isDebugEnabled())
      log.debug("getServerAliases: " + issuers);
    return new String [] {nodealias};
  }

  public String getName() {
    return NodeInfo.getNodeName();
  }
 
  public void invalidate(String cname) {
    if (log.isInfoEnabled()) {
      log.info("Received invalidate notification for: " + cname);
    }
    updateKeystore();
  }

  public void updateCertificate() {
    updateKeystore();
  }

  protected void setManagerReady() {
  }
}
