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

import java.net.PasswordAuthentication;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import javax.swing.JOptionPane;

import org.cougaar.core.security.crypto.CertificateCache;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.ssl.ui.UserAliasPwdDialog;

public class KeyRingUserAuthImpl extends AuthenticationHandler {
  protected CertificateCacheService cacheService = null;
  protected CertAuthListener authListener = null;
  protected String useralias = "";

  public KeyRingUserAuthImpl(CertificateCacheService cacheservice) {
    this.cacheService = cacheservice;
  }

  protected PasswordAuthentication getUserAliasPwd(String username) {
    UserAliasPwdDialog dialog = new UserAliasPwdDialog();
    dialog.setAlias(username);

    ArrayList aliasList = new ArrayList();
    Enumeration aliases = cacheService.getAliasList();
    while (aliases.hasMoreElements()) {
      try {
	String alias = (String)aliases.nextElement();
	java.security.cert.Certificate[] certChain = cacheService.getCertificateChain(alias);
	if (certChain.length <= 1)
	  continue;
	String dname = ((X509Certificate)certChain[0]).getSubjectDN().getName();
	String title = CertificateUtility.findAttribute(dname, "t");
	if (!title.equals(CertificateCache.CERT_TITLE_USER))
	  continue;
	aliasList.add(alias + " (" + dname + ")");
      }
      catch (KeyStoreException ksx) {}
    }
    
    dialog.setAliasList(aliasList);
    dialog.setHost(requestUrl);

    boolean ok = dialog.showDialog();

    if (!ok) return null;

    return new PasswordAuthentication(dialog.getAlias(),
      dialog.getPwd());
  }

  public String getDescription() {
    return "Certificate authentication";
  }

  public String getDetailDescription() {
    return "Retrieves certificate from keystore with user alias and password, "
      + "and use it in SSL connections.";
  }

  /**
   * username should be the same as user alias
   */
  public String getUserName() {
    return useralias;
  }

  public void setUserName(String username) {
    useralias = username;
  }

  public void setAuthListener(AuthenticationListener listener) {
    authListener = (CertAuthListener)listener;
  }

  protected boolean loginUser(String alias, char [] password)
    throws Exception
  {
    boolean login = false;
    useralias = alias;

    while (!login) {
      PasswordAuthentication pa = new PasswordAuthentication(alias, password);
      if (password.length == 0) {
        pa = getUserAliasPwd(alias);
        if (pa == null)
          break;
        alias = pa.getUserName();
      }

      // will throw exception if fatal error occurs, such as keystore problem
      try {
        PrivateKey privatekey = (PrivateKey)cacheService.getKey(alias, pa.getPassword());
        if (privatekey != null) {
          // install into certcache, but does not validate
          // later on the getCertificateChain will be called
          X509Certificate userx509 = (X509Certificate)cacheService.getCertificate(alias);

          if (authListener != null) {
            authListener.setAlias(alias);
            authListener.setPrivateKey(privatekey);
            authListener.setCertificate(userx509);
          }
          useralias = alias;
          login = true;
        }
      } catch (Exception ex) {
        // throw exception if not password incorrect
        if (!(ex instanceof UnrecoverableKeyException))
          throw ex;

        JOptionPane.showMessageDialog(null, "Authentication fail.\n Please check userid and password.",
          "Certificate Authentication", JOptionPane.ERROR_MESSAGE);
      }
    }
    return login;
  }

  public void authenticateUser(String username)
    throws Exception {
    authenticated = loginUser(username, new char [] {});
    // clean password?
  }
}
