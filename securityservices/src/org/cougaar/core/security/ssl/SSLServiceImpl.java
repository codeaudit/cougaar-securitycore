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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.SSLService;
import org.cougaar.core.service.LoggingService;

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
