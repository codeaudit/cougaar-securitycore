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

import org.cougaar.core.security.ssl.ui.UserAliasPwdDialog;

import java.net.PasswordAuthentication;

public class BasicAuthHandler extends AuthenticationHandler {
  String username = "";
  PasswordAuthentication _pa = null;
  AuthenticationListener listener = null;

  public BasicAuthHandler() {
  }

  public void setAuthListener(AuthenticationListener listener) {
    this.listener = listener;
  }

  public void authenticateUser(String username) throws Exception
  {
    PasswordAuthentication pa = null;
    if (_pa == null) {
      UserAliasPwdDialog dialog = new UserAliasPwdDialog();
      dialog.setAlias(username);
      dialog.hideLookup();
      dialog.setPrompt("\nPlease enter the password to access the remote site.");
      dialog.setHost(requestUrl);

      boolean ok = dialog.showDialog();
      char[] pwd = dialog.getPwd();
      username = dialog.getAlias();
      if (ok) {
        pa = new PasswordAuthentication(username, pwd);
        if (dialog.isCached()) {
          _pa = pa;
        }
      }
      else {
        pa = null;
      }
    }
    else {
      //System.out.println("trying with previous ...");
      pa = _pa;
    }

    if (listener != null)
      listener.setPasswordAuthentication(pa);
  }

  public String getUserName() {
    return username;
  }

  public void setRequestingURL(String url) {
    // if the same url is asking for password,
    // the previous password is incorrect
    // reset password
    if (requestUrl != null && requestUrl.equals(url)) {
      //System.out.println("retrying ...");
      _pa = null;
    }
    super.setRequestingURL(url);
  }

  public void setUserName(String username) {
    this.username = username;
  }

  public void setPassword(char [] password) {
    _pa = new PasswordAuthentication(username, password);
  }

  public String getDescription() {
    return "Basic password authentication";
  }

  public String getDetailDescription() {
    return "The simple prompt for username and password.";
  }

  public boolean authenticateAtLogin() {
    return false;
  }

}
