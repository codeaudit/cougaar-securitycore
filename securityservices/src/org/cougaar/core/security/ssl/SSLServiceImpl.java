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
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.SSLService;
import org.cougaar.core.service.LoggingService;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

public class SSLServiceImpl implements SSLService {
  // may need to move to crypto policy file?
  public static final String SSLContextProtocol = "TLS";
  protected String protocol = SSLContextProtocol;

  protected static SSLContext sslcontext = null;
  protected KeyManager km = null;
  protected TrustManager tm = null;
  protected
 ServiceBroker serviceBroker;
  protected LoggingService log;

  public SSLServiceImpl(ServiceBroker sb)
  {
    serviceBroker = sb;
    log = (LoggingService)
	serviceBroker.getService(this,
	LoggingService.class, null);
  }

  public void setProtocol(String protocol) {
    this.protocol = protocol;
  }

  public synchronized void init(KeyRingService krs)
    throws Exception
  {
    if (sslcontext != null)
      return;

    // create context
    SSLContext context = SSLContext.getInstance(protocol);

    // create keymanager and trust manager
    km = new KeyManager(krs, serviceBroker);
    tm = new TrustManager(krs, serviceBroker);

    context.init(new KeyManager[] {km}, new TrustManager[] {tm}, null);
    sslcontext = context;

    KeyRingSSLFactory.init(sslcontext);
    KeyRingSSLServerFactory.init(sslcontext);

    // set default connection socket factory
    HttpsURLConnection.setDefaultSSLSocketFactory(
      (SSLSocketFactory)KeyRingSSLFactory.getDefault());

    if (log.isDebugEnabled())
      log.debug("Successfully created SSLContext.");

  }

  public void updateKeystore() {
    if (km != null && tm != null) {
      km.updateKeystore();
      tm.updateKeystore();
    }
  }

}
