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

  public void authenticateUser(String username, char [] password) throws Exception
  {
    _pa = new PasswordAuthentication(username, password);
  }

  public void authenticateUser(String username) throws Exception
  {
    PasswordAuthentication pa = null;
    //if (_pa.getPassword().length == 0) {
    /*
      String pwd = JOptionPane.showInputDialog(
        "Please enter the password for user " + username + ".");
        */
      UserAliasPwdDialog dialog = new UserAliasPwdDialog();
      dialog.setAlias(username);
      dialog.setPrompt("\nPlease enter the password to access the remote site.");

      boolean ok = dialog.showDialog();
      char[] pwd = dialog.getPwd();
      username = dialog.getAlias();
      if (ok)
        pa = new PasswordAuthentication(username, pwd);
      else
        pa = null;
    /*
    }
    else
      pa = _pa;
      */

    if (listener != null)
      listener.setPasswordAuthentication(pa);
  }

  public String getUserName() {
    return username;
  }

  public void setUserName(String username) {
    this.username = username;
    _pa = new PasswordAuthentication(username, new char[] {});
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