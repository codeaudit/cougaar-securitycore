package org.cougaar.core.security.userauth;

import org.cougaar.core.security.ssl.ui.*;

import java.net.*;
import javax.swing.*;

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