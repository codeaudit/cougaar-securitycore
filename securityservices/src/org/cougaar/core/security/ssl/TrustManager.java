package org.cougaar.core.security.ssl;

import javax.net.ssl.*;
import java.security.*;
import java.security.cert.*;

import com.nai.security.util.*;
import com.nai.security.crypto.DirectoryKeyStore;
import org.cougaar.core.security.services.crypto.KeyRingService;

public class TrustManager implements X509TrustManager {
  KeyRingService keyRing = null;
  DirectoryKeyStore keystore = null;
  X509Certificate [] issuers;

  public TrustManager(KeyRingService krs) {
    keyRing = krs;
    keystore = keyRing.getDirectoryKeyStore();

    //updateKeystore();
  }

  public synchronized void updateKeystore() {
    String nodename = NodeInfo.getNodeName();
    try {
      X509Certificate nodex509 = (X509Certificate)keyRing.findCert(nodename);
      if (nodex509 != null) {
        issuers = keystore.checkCertificateTrust(nodex509);
      }
    } catch (Exception ex) {
      if (CryptoDebug.debug)
        ex.printStackTrace();
      issuers = new X509Certificate[] {};
    }
  }

  /**
   * Given the partial or complete certificate chain provided by the peer,
   * build a certificate path to a trusted root and return if it
   * can be validated and is trusted for client SSL authentication based
   * on the authentication type.
   */

  public void checkClientTrusted(X509Certificate[] chain, String authType) {
    if (CryptoDebug.debug)
      System.out.println("checkClientTrusted: " + chain);
    // check whether cert is valid, then build the chain
    try {
      if (chain.length == 0)
        return;
      X509Certificate [] certchain = keystore.checkCertificateTrust(chain[0]);
    } catch (Exception e) {
      if (CryptoDebug.debug)
        e.printStackTrace();
    }
  }

  /**
   * Given the partial or complete certificate chain provided by the peer,
   * build a certificate path to a trusted root and return if it
   * can be validated and is trusted for server SSL authentication based on
   * the authentication type.
   */
  public void checkServerTrusted(X509Certificate[] chain, String authType) {
    // check whether cert is valid, then build the chain
    if (CryptoDebug.debug)
      System.out.println("checkServerTrusted: " + chain);

    try {
      if (chain.length == 0)
        return;
      X509Certificate [] certchain = keystore.checkCertificateTrust(chain[0]);
    } catch (Exception e) {
      if (CryptoDebug.debug)
        e.printStackTrace();
    }
  }

  /**
   * Only the CA in the Cougaar society for now
   */
  public X509Certificate[] getAcceptedIssuers() {
    // get all CA from the client cryptoPolicy and their parent CAs
    // how about trusted CA?
    // since node configuration has only one CA, the issues will only
    // be one CA and the node itself
    if (CryptoDebug.debug)
      System.out.println("getAcceptedIssuers.");
    return issuers;
  }
}