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


package org.cougaar.core.security.userauth;

import java.util.Enumeration;
import java.util.Vector;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.UserSSLService;
import org.cougaar.core.security.ssl.ui.AuthSchemeDialog;
import org.cougaar.core.service.LoggingService;

/**
 * This is the default implementation of UserAuthenticator
 *
 * The authenticator collects registration of authentication handlers,
 * prompt user to select them.
 *
 * The user application is also responsible for the registration
 * of handlers and setting the handlers for the appropriate party
 * requiring authentication. This class providers the default
 * initialization which sets up SSL, HTTP authentication handlers.
 *
 * To use this class:
 *
 * 1. create new instance.
 * 2. call the init method, or subclass this to change the init method.
 *
 */
public class UserAuthenticatorImpl
  extends UserAuthenticator
{
  protected Vector selectedHandlers = new Vector();
  protected String username = null;
  ServiceBroker serviceBroker;
  protected LoggingService log=null;

  public UserAuthenticatorImpl(String username) {
    this.username = username;
  }

  /**
   * default initialization
   */
  public void init(SecurityServiceProvider secProvider) {
    try {
      if (secProvider != null) {
        serviceBroker = secProvider.getServiceBroker();
        UserSSLService userservice = (UserSSLService)
	  serviceBroker.getService(this, UserSSLService.class, null);
	 log = (LoggingService)
	   serviceBroker.getService(this,
				    LoggingService.class, null);
	 CertificateCacheService cacheservice=(CertificateCacheService)
	   serviceBroker.getService(this,
				   CertificateCacheService.class,
				    null);
	 
	if(cacheservice==null) {
	  log.warn("Unable to get Certificate cache Service in init of UserAuthenticatorImpl");
	}
        // handler for certificates
        KeyRingUserAuthImpl certhandler = new KeyRingUserAuthImpl(cacheservice);
        registerHandler(certhandler);
        userservice.setAuthHandler(certhandler);
      }
    } catch (Exception ex) {}

    BasicAuthHandler passhandler = new BasicAuthHandler();
    registerHandler(passhandler);
    // handler for password authentication needs
    UserPasswordAuthenticator pa =
      new UserPasswordAuthenticator(serviceBroker);
    pa.setAuthHandler(passhandler);
  }

  public UserAuthenticatorImpl() {
    username = "";
    SecurityServiceProvider secProvider = null;
    try {
      secProvider = new SecurityServiceProvider();
    } catch (Exception ex) {
    }
    init(secProvider);

    try {
      authenticateUser();
    } catch (Exception ex) {}
  }

  // authenticate with password authentication only
  public boolean authenticateWithPassword(String username, char [] password) {
    for (Enumeration e = handlers.elements(); e.hasMoreElements(); ) {
      AuthenticationHandler handler = (AuthenticationHandler)
        e.nextElement();
      if (handler instanceof BasicAuthHandler) {
        BasicAuthHandler passHandler = (BasicAuthHandler)handler;
        passHandler.setUserName(username);
        passHandler.setPassword(password);
        return true;
      }
    }
    return false;
  }

  public boolean authenticateUser() throws Exception {
    if (handlers.size() == 0)
      return false;

    if (selectedHandlers.size() == 0) {
      AuthSchemeDialog dialog = new AuthSchemeDialog(serviceBroker);
      Vector handlerlist = new Vector();
      for (Enumeration e = handlers.elements(); e.hasMoreElements(); )
        handlerlist.addElement(e.nextElement());

      dialog.setHandlers(handlerlist);
      if (dialog.showDialog()) {
        selectedHandlers = dialog.getSelection();
      }
    }

    if (selectedHandlers.size() == 0)
      return false;

    for (int i = 0; i < selectedHandlers.size(); i++) {
      AuthenticationHandler handler = (AuthenticationHandler)
        selectedHandlers.get(i);
      handler.setUserName(username);
      if (handler.authenticateAtLogin()) {
        handler.authenticateUser(username);
        if (!handler.isAuthenticated())
          return false;
      }
    }
    return true;
  }

  // this makes batch testing simpler
  public void setAuthenticateHandlers(String [] handlecls) {
    for (int i = 0; i < handlecls.length; i++)
      selectedHandlers.addElement(handlers.get(handlecls[i]));
  }

}
