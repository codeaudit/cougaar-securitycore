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
import org.cougaar.core.security.crypto.DirectoryKeyStore;
import org.cougaar.core.security.services.crypto.KeyRingService;

public final class ServerKeyManager extends org.cougaar.core.security.ssl.KeyManager {
  public ServerKeyManager(KeyRingService krs) {
    super(krs);
  }

  public synchronized void updateKeystore() {
    // find the valid hostname, get key alias and server certificate
    // use nodealias to set server alias which is the hostname
    String hostname = keystore.getHostName();
    nodename = hostname;
    System.out.println("=====> getHostName: " + hostname);
    PrivateKey svrprivatekey = keyRing.findPrivateKey(hostname);
    if (svrprivatekey != null) {
      nodex509 = (X509Certificate)keyRing.findCert(hostname);
      nodealias = keystore.findAlias(hostname);
    System.out.println("=====> alias: " + nodealias);
    }
  }

  public String chooseClientAlias(String keyType, Principal[] issuers, Socket socket) {
    // server application has no client alias
    return null;
  }

  public String[] getClientAliases(String keyType, Principal[] issuers) {
    return new String [] {};
  }


}