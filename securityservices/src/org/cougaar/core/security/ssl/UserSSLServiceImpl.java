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

import javax.net.*;
import javax.net.ssl.*;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.userauth.*;

public class UserSSLServiceImpl
  extends SSLServiceImpl
  implements UserSSLService
{
  private SSLContext usrcontext = null;

  public UserSSLServiceImpl(ServiceBroker sb) {
    super(sb);
  }

  public synchronized void init(KeyRingService krs)
    throws Exception
  {
    // create context
    SSLContext context = SSLContext.getInstance(protocol);

    // create keymanager and trust manager
    km = new UserKeyManager(krs, serviceBroker);
    tm = new UserTrustManager(krs, serviceBroker);

    context.init(new KeyManager[] {km}, new TrustManager[] {tm}, null);

    usrcontext = context;

    // set default connection socket factory
    HttpsURLConnection.setDefaultSSLSocketFactory(
      (SSLSocketFactory)getUserSocketFactory());

    log.debug("Successfully initialize UserSSLService.");
  }

  public SocketFactory getUserSocketFactory() {
    return KeyRingSSLFactory.getInstance(usrcontext);
  }

  public void setAuthHandler(AuthenticationHandler handler) {
    ((UserKeyManager)km).setAuthHandler(handler);
  }

}
