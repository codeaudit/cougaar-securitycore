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

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.security.util.*;
import org.cougaar.core.security.crypto.DirectoryKeyStore;
import org.cougaar.core.security.crypto.PrivateKeyCert;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.services.crypto.KeyRingService;

public final class ServerKeyManager
  extends org.cougaar.core.security.ssl.KeyManager {
  public ServerKeyManager(KeyRingService krs, ServiceBroker sb)
    throws CertificateException
  {
    super(krs, sb);

    if (nodex509 == null || nodealias == null) {
      log.warn("No valid server certificate");
      throw new CertificateException("No valid server certificate.");
    }
  }

  /*
  public synchronized void updateKeystore() {
    // find the valid hostname, get key alias and server certificate
    // use nodealias to set server alias which is the hostname
    String hostname = getName();
    nodename = hostname;

    //log.debug("=====> getHostName: " + hostname);

    // node will generate host certificate
    //keyRing.checkOrMakeCert(hostname);

    List nodex509List = keyRing.findCert(hostname);
    if (nodex509List != null && nodex509List.size() > 0) {
      nodex509 = ((CertificateStatus)nodex509List.get(0)).getCertificate();
    }
    nodealias = keystore.findAlias(hostname);

    if (log.isDebugEnabled())
      log.debug("WeberserverSSLContext:KeyManager: nodealias is " + nodealias
			 + " and nodex509 is " + nodex509);
  }
  */

  public String chooseClientAlias(String keyType, Principal[] issuers, Socket socket) {
    // server application has no client alias
    return null;
  }

  public String[] getClientAliases(String keyType, Principal[] issuers) {
    return new String [] {};
  }

  public String getName() {
    return keystore.getHostName();
  }

}
