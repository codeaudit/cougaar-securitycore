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

package org.cougaar.core.security.userauth;

import java.util.*;

// Cougaar core infrastructure
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.*;

// Cougaar security services
import org.cougaar.core.security.ssl.ui.*;
import org.cougaar.core.security.provider.*;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.crypto.*;

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
  private ServiceBroker serviceBroker;
  private LoggingService log;

  public UserAuthenticatorImpl(String username) {
    this.username = username;
  }

  public UserAuthenticatorImpl() {
    username = "";
    SecurityServiceProvider secProvider = null;
    try {
      secProvider = new SecurityServiceProvider();
      serviceBroker = secProvider.getServiceBroker();
      log = (LoggingService)
	serviceBroker.getService(this, LoggingService.class, null);
    } catch (Exception ex) {
      if (log != null) {
	log.warn("Unable to create UserAuthenticatorImpl: " + ex);
      }
      throw new RuntimeException("Unable to create UserAuthenticatorImpl: " + ex);
    }
    init(secProvider);

    try {
      authenticateUser();
    } catch (Exception ex) {
      if (log != null) {
	log.warn("Unable to authenticate user: " + ex);
      }
    }
  }

  /**
   * default initialization
   */
  public void init(SecurityServiceProvider secProvider) {
    try {
      if (secProvider != null) {
	if (serviceBroker == null) {
	  serviceBroker = secProvider.getServiceBroker();
	}
	if (log == null) {
	  log = (LoggingService)
	    serviceBroker.getService(this, LoggingService.class, null);
	}
        KeyRingService keyRing = (KeyRingService)
                                          secProvider.getService(serviceBroker,
                                                         this,
                                                         KeyRingService.class);

        UserSSLService userservice = (UserSSLService)
                                          secProvider.getService(serviceBroker,
                                                   this,
                                                   UserSSLService.class);

        // handler for certificates
	if (keyRing != null) {
	  KeyRingUserAuthImpl certhandler = new KeyRingUserAuthImpl(keyRing.getKeyStore());
	  registerHandler(certhandler);
	  userservice.setAuthHandler(certhandler);
	}
      }
    } catch (Exception ex) {
      log.warn("Unable to initialize UserAuthenticatorImpl:" + ex);
    }

    BasicAuthHandler passhandler = new BasicAuthHandler();
    registerHandler(passhandler);
    // handler for password authentication needs
    UserPasswordAuthenticator pa =
      new UserPasswordAuthenticator(serviceBroker);
    pa.setAuthHandler(passhandler);
  }

  public boolean authenticateUser() throws Exception {
    if (handlers.size() == 0)
      return false;

    if (selectedHandlers.size() == 0) {
      AuthSchemeDialog dialog = new AuthSchemeDialog();
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
