package org.cougaar.core.security.ssl;

import javax.net.ssl.*;
import java.security.*;
import java.security.cert.*;
import java.net.*;

import com.nai.security.util.*;
import com.nai.security.crypto.DirectoryKeyStore;
import org.cougaar.core.security.services.crypto.KeyRingService;

public final class KeyManager implements X509KeyManager {
  private KeyRingService keyRing = null;
  private String nodealias = null;
  private X509Certificate nodex509 = null;
  private DirectoryKeyStore keystore = null;
  private String nodename = null;
  // provides the default implementation, but it can be overwritten
  private UserCertificateUI userUI = new UserCertificateUIImpl();

  public KeyManager(KeyRingService krs, DirectoryKeyStore ks) {
    keyRing = krs;
    keystore = ks;

    // get nodename, nodealias, and node certificate
    updateKeystore();
  }

  public void setUserCertificateUI(UserCertificateUI userUI) {
    this.userUI = userUI;
  }

  public synchronized void updateKeystore() {
    // is the nodeinfo way of retrieving nodename from system property appropriate?
    nodename = NodeInfo.getNodeName();

    // get the certificates for the nodename
    // get the last valid certificate
    // use DirectoryKeyStore's functions (it assumes there is only one matching
    // between commonName and cert/alias)
    nodealias = keystore.findAlias(nodename);
    nodex509 = (X509Certificate)keyRing.findCert(nodename);
  }

  /**  Choose an alias to authenticate the client side of a secure socket
   *   given the public key type and the list of certificate issuer
   *   authorities recognized by the peer (if any).
   */
  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    // node alias if opening socket for RMI... node service
    // if server is tomcat prompt for user certificate
    return nodealias;
  }

  /**
   * Choose an alias to authenticate the server side of a secure socket
   * given the public key type and the list of certificate
   * issuer authorities recognized by the peer (if any).
   */
  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    // if tomcat return tomcat alias
    return nodealias;
  }

  /**
   * Returns the certificate chain associated with the given alias.
   */
  public X509Certificate[] getCertificateChain(String alias) {
    // should be only asking for node's chain for now
    if (CryptoDebug.debug)
      System.out.println("getCertificateChain: " + alias);

    if (alias.equals(nodealias) && nodex509 != null) {
      try {
        return keystore.checkCertificateTrust(nodex509);
      } catch (Exception e) {
        if (CryptoDebug.debug)
          e.printStackTrace();
      }
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
    return new String [] {nodealias};
  }

  /**
   * Returns the key associated with the given alias.
   */
  public PrivateKey getPrivateKey(String alias) {
    // only find for node, why would agent certificate be asked?
    if (CryptoDebug.debug)
      System.out.println("getPrivateKey: " + alias);

    if (!alias.equals(nodealias) || nodealias == null)
      return null;

    // DirectoryKeyStore sends out request if key not found
    return keyRing.findPrivateKey(nodename);
  }

  /**
   * Returns all aliases of node and agent
   */
  public String[] getServerAliases(String keyType, Principal[] issuers) {
    // node and agent aliases?
    return new String [] {nodealias};
  }


}