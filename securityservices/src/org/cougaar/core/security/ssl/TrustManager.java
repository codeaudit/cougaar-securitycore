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
import java.util.*;

import org.cougaar.core.security.util.*;
import org.cougaar.core.security.crypto.DirectoryKeyStore;
import org.cougaar.core.security.services.crypto.KeyRingService;

public class TrustManager implements X509TrustManager {
  protected KeyRingService keyRing = null;
  protected DirectoryKeyStore keystore = null;
  protected X509Certificate [] issuers;

  public TrustManager(KeyRingService krs) {
    keyRing = krs;
    keystore = keyRing.getDirectoryKeyStore();

    updateKeystore();
  }

  public synchronized void updateKeystore() {
    try {
      issuers = keystore.getTrustedIssuers();
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

  public void checkClientTrusted(X509Certificate[] chain, String authType)
    throws CertificateException
  {
    if (CryptoDebug.debug)
      System.out.println("checkClientTrusted: " + chain);

    // TODO: check whether client is user or node

    // check whether cert is valid, then build the chain
    keystore.checkCertificateTrust(chain[0]);
  }

  /**
   * Given the partial or complete certificate chain provided by the peer,
   * build a certificate path to a trusted root and return if it
   * can be validated and is trusted for server SSL authentication based on
   * the authentication type.
   */
  public void checkServerTrusted(X509Certificate[] chain, String authType)
    throws CertificateException
  {
    // check whether cert is valid, then build the chain
    if (CryptoDebug.debug)
      System.out.println("checkServerTrusted: " + chain);

    // TODO: check whether cert is of type node or server

    keystore.checkCertificateTrust(chain[0]);
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