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

public abstract class AuthenticationHandler {
  protected boolean authenticated = false;
  protected String requestUrl = null;

  /**
   * short description to show on list box
   */
  public abstract String getDescription();

  public abstract String getDetailDescription();

  /**
   * There is two ways to authenticate user:
   * 1. authenticate at login, this applies to authentication
   *    which can be verify locally, i.e., certificate
   *
   * 2. authenticate at access, this applies to authentication
   *    required when access remote modules.
   */

  /**
   * Default to be called by UserAuthenticator
   */
  public abstract void authenticateUser(String name) throws Exception;

  public abstract void setAuthListener(AuthenticationListener listener);

  public abstract String getUserName();

  public abstract void setUserName(String username);

  public boolean isAuthenticated() {
    return authenticated;
  }

  public String toString() {
    return getDescription();
  }

  public boolean authenticateAtLogin() {
    return true;
  }

  public void setRequestingURL(String url) {
    requestUrl = url;
  }
}