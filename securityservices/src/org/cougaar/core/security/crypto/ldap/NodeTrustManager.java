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
package org.cougaar.core.security.crypto.ldap;

import javax.net.ssl.*;
import java.security.*;
import java.security.cert.*;

import com.nai.security.util.*;
import org.cougaar.core.security.services.crypto.KeyRingService;

public class NodeTrustManager implements X509TrustManager {
  KeyRingService _krs      = null;
  String         _nodeName = null;

  public NodeTrustManager(KeyRingService krs) {
    _krs      = krs;
    _nodeName = NodeInfo.getNodeName();
  }

  /**
   * Given the partial or complete certificate chain provided by the peer,
   * build a certificate path to a trusted root and return if it
   * can be validated and is trusted for client SSL authentication based
   * on the authentication type.
   */

  public void checkClientTrusted(X509Certificate[] chain, String authType) 
    throws CertificateException {
    checkServerTrusted(chain,authType);
  }

  /**
   * Given the partial or complete certificate chain provided by the peer,
   * build a certificate path to a trusted root and return if it
   * can be validated and is trusted for server SSL authentication based on
   * the authentication type.
   */
  public void checkServerTrusted(X509Certificate[] chain, String authType) 
    throws CertificateException {
    // check whether cert is valid, then build the chain
    X509Certificate [] certchain = null;
    try {
      if (chain.length != 0)
        certchain = _krs.findCertChain(chain[0]);
    } catch (Exception e) {
      if (CryptoDebug.debug)
        e.printStackTrace();
    }
    if (certchain == null) {
      throw new CertificateException("The certificate chain is not trusted");
    }
  }

  /**
   * Only the CA in the Cougaar society for now
   */
  public X509Certificate[] getAcceptedIssuers() {
    // for now there is only one X.509 certificate returned for a
    // given common name. In the future, you'll have to add all accepted
    // certs.
    X509Certificate nodex509 = (X509Certificate)_krs.findCert(_nodeName);
    if (nodex509 != null) {
      return _krs.findCertChain(nodex509);
    }
    return new X509Certificate[0]; // no cert, no trust
  }
}
