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
import java.net.*;

import com.nai.security.util.*;
import org.cougaar.core.security.services.crypto.KeyRingService;

public final class NodeKeyManager implements X509KeyManager {
  private KeyRingService  _krs;
  private String          _nodeName;
  private String[]        _nodeNameArr;

  public NodeKeyManager(KeyRingService krs) {
    _krs = krs;

    // get nodename, and node certificate
    _nodeName = NodeInfo.getNodeName();
    _nodeNameArr = new String[] { _nodeName };

    // ensure that there is a PrivateKey for the node now.
    _krs.findPrivateKey(_nodeName);
  }

  /**
   *   Choose an alias to authenticate the client side of a secure socket
   *   given the public key type and the list of certificate issuer
   *   authorities recognized by the peer (if any).
   */
  public String chooseClientAlias(String[] keyType, Principal[] issuers, 
                                  Socket socket) {
    if (keyType == null) {
      String aliases[] = getClientAliases(null, issuers);
      if (aliases != null && aliases.length == 0) {
        return aliases[0]; // just the first one is fine.
      }
    } else {
      for (int i = 0; i < keyType.length; i++) {
        String aliases[] = getClientAliases(keyType[i], issuers);
        if (aliases != null && aliases.length > 0) {
          return aliases[0]; // the first one is just fine
        }
      }
    }
    return null;
  }

  /**
   * Choose an alias to authenticate the server side of a secure socket
   * given the public key type and the list of certificate
   * issuer authorities recognized by the peer (if any).
   */
  public String chooseServerAlias(String[] keyType, Principal[] issuers,
                                  Socket socket) {
    if (keyType == null) {
      String aliases[] = getServerAliases(null, issuers);
      if (aliases != null && aliases.length == 0) {
        return aliases[0]; // just the first one is fine.
      }
    } else {
      for (int i = 0; i < keyType.length; i++) {
        String aliases[] = getServerAliases(keyType[i], issuers);
        if (aliases != null && aliases.length > 0) {
          return aliases[0]; // the first one is just fine
        }
      }
    }
    return null;
  }

  /**
   * Choose an alias to authenticate the server side of a secure socket
   * given the public key type and the list of certificate
   * issuer authorities recognized by the peer (if any).
   */
  public String chooseServerAlias(String keyType, Principal[] issuers, 
                                  Socket socket) {
    String aliases[] = getServerAliases(keyType, issuers);
    if (aliases != null && aliases.length > 0) {
      return aliases[0]; // the first one is just fine
    }
    return null;
  }

  /**
   * Returns the certificate chain associated with the given alias.
   */
  public X509Certificate[] getCertificateChain(String alias) {
    // should be only asking for node's chain for now
    if (CryptoDebug.debug)
      System.out.println("getCertificateChain: " + alias);

    if (alias != null && alias.equals(_nodeName)) {
      return _krs.findCertChain((X509Certificate)_krs.findCert(_nodeName));
    }
    return null; // don't support that alias
  }

  /**
   * Get the matching aliases for authenticating the client side of
   * a secure socket given the public key type and the list of
   * certificate issuer authorities recognized by the peer (if any).
   */
  public String[] getClientAliases(String keyType, Principal[] issuers) {
    // node and agent aliases?
    return _nodeNameArr;
  }

  /**
   * Returns all aliases of node and agent
   */
  public String[] getServerAliases(String keyType, Principal[] issuers) {
    // node and agent aliases?
    return _nodeNameArr;
  }

  /**
   * Returns the key associated with the given alias.
   */
  public PrivateKey getPrivateKey(String alias) {
    // only find for node, why would agent certificate be asked?
    if (CryptoDebug.debug)
      System.out.println("getPrivateKey: " + alias);

    if (alias == null || !alias.equals(_nodeName))
      return null;

    return _krs.findPrivateKey(_nodeName);
  }
}
