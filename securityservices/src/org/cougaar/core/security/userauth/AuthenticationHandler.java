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
