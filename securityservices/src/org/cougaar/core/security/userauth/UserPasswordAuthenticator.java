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

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

import java.net.*;
import org.cougaar.core.security.util.CryptoDebug;

public final class UserPasswordAuthenticator extends Authenticator
  implements AuthenticationListener {
  private PasswordAuthentication _pa = null;
  private AuthenticationHandler handler;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  public UserPasswordAuthenticator(ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    Authenticator.setDefault(this);
  }

  public void setAuthHandler(AuthenticationHandler handler) {
    this.handler = handler;
    handler.setAuthListener(this);
  }

  /**
   * return this for any criteria
   */
  public void setPasswordAuthentication(PasswordAuthentication pa) {
    _pa = pa;
  }

  /**
   * return this base on selected criteria
   */
  /*
  public void setPasswordAuthentication(
    String host, String port, String protocol, String username, char [] password) {
  }
  */

  /**
   * prompt user on selected criteria, if prompt is null use the prompt from the site
   */
  /*
  public void setPasswordAuthentication(
    String host, String port, String protocol, String prompt) {
  }
  */

  public PasswordAuthentication getPasswordAuthentication() {
    if (log.isDebugEnabled())
      log.debug("password? " + _pa + " : " + handler);
    //if (_pa == null && handler != null && trial < 3) {
    if (handler != null) {
      try {
        handler.authenticateUser(handler.getUserName());
      } catch (Exception ex) {}
    }

    // should have a table of password authentication based on
    // host, port, protocol, etc
    if (log.isDebugEnabled())
      log.debug("password: " + _pa);
    return _pa;
  }
}
