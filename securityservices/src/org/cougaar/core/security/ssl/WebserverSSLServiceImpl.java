/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 

package org.cougaar.core.security.ssl;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLContext;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.identity.WebserverIdentityService;

public class WebserverSSLServiceImpl
  extends SSLServiceImpl
  implements WebserverIdentityService {

  private static SSLContext srvcontext = null;

  public WebserverSSLServiceImpl(ServiceBroker sb) {
    super(sb);
  }

  public synchronized void init(KeyRingService krs)
    throws Exception
  {
    if (srvcontext != null) {
      return;
    }

    // create context
    SSLContext context = SSLContext.getInstance(protocol);

    // create keymanager and trust manager
    km = new ServerKeyManager(krs, serviceBroker);
    tm = new ServerTrustManager(krs, serviceBroker, true);

    context.init(new KeyManager[] {km}, new TrustManager[] {tm}, null);

    srvcontext = context;

    // get property for webserver socket factory if to make this
    // flexible for any webservers
    WebtomcatSSLServerFactory.init(this);

    if (log.isDebugEnabled())
      log.debug("Successfully created Webserver SSLContext.");
  }

  public ServerSocketFactory getWebServerSocketFactory() {
    return KeyRingSSLServerFactory.getInstance(srvcontext);
  }
}
