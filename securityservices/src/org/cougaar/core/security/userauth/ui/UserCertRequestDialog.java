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

package org.cougaar.core.security.userauth.ui;

import java.awt.BorderLayout;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.PrivateKeyCert;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.util.UIUtil;
import org.cougaar.core.service.LoggingService;

import sun.security.x509.X500Name;

public class UserCertRequestDialog extends JDialog {
  BorderLayout borderLayout1 = new BorderLayout();
  JPanel buttonPanel = new JPanel();
  JButton nextButton = new JButton();
  JButton cancelButton = new JButton();
  UserProfilePanel profilePanel;
  PasswordPanel pwdPanel;

  int panelIndex = 0;
  boolean isOk = false;

  ServiceBroker serviceBroker;
  JTabbedPane jTabbedPane1 = new JTabbedPane();
  
  protected LoggingService log;
  KeyRingService keyRing;

  public UserCertRequestDialog(ServiceBroker sb) {
    super((Frame)null, "User Certificate Request", true);

    serviceBroker = sb;
    // if keyring is not available auth dialog should not
    // even show up!
    keyRing = (KeyRingService)
      serviceBroker.getService(this,
			       KeyRingService.class,
			       null);
     log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    try {
      jbInit();

      loadRequest();

      setButtonListeners();

      setSize(400, 300);

      UIUtil.centerWindow(this);

    }
    catch(Exception e) {
      e.printStackTrace();
    }
  }

  private void setButtonListeners() {
    nextButton.addActionListener(createButtonListener());
    cancelButton.addActionListener(createButtonListener());

    profilePanel.requestBox.addActionListener(createListListener());
  }

  private ActionListener createButtonListener() {
    return new ActionListener() {
      public void actionPerformed(ActionEvent evt) {
        processButtonEvent(evt);
      }
    };
  }

  private ActionListener createListListener() {
    return new ActionListener() {
      public void actionPerformed(ActionEvent evt) {
        processListEvent(evt);
      }
    };
  }

  public boolean showDialog() {
    setVisible(true);
    return isOk;
  }

  private void setCaDNs(java.util.List caDNs) {
    for (int i = 0; i < caDNs.size(); i++) {
      String cadn = (String)caDNs.get(i);
      profilePanel.dnlist.addElement(cadn);
    }
    profilePanel.cadnBox.updateUI();
    profilePanel.cadnBox.setSelectedIndex(0);
  }

  private String getCaDN() {
    int index = profilePanel.cadnBox.getSelectedIndex();
    return (String)profilePanel.dnlist.get(index);
  }

  private char [] getPwd() {
    return pwdPanel.jPasswordField1.getPassword();
  }

  private void loadRequest() {
    // get user certificates
    if (keyRing == null) {
      JOptionPane.showMessageDialog(null, "The cryptographic service is not initialized properly",
				    "Configuration error", JOptionPane.ERROR_MESSAGE, null);
      throw new RuntimeException("The cryptographic service is not initialized properly");
    }
     CertificateCacheService cacheservice=(CertificateCacheService)
       serviceBroker.getService(this,
			       CertificateCacheService.class,
			       null);
     
  if(cacheservice==null) {
     log.warn("Unable to get Certificate cache Service in loadRequest");
  }
  
  try {

    //KeyStore keystore = keyRing.getKeyStore();
    Enumeration aliases = null;
    if(cacheservice!=null) {
      cacheservice.getAliasList();
    }
    if(aliases!=null){
      for (; aliases.hasMoreElements(); ) {
        String alias = (String)aliases.nextElement();
        java.security.cert.Certificate [] certChain = cacheservice.getCertificateChain(alias);
        if (certChain.length == 0)
          continue;
        String dname = ((X509Certificate)certChain[0]).getSubjectDN().getName();
        String title = CertificateUtility.findAttribute(dname, "t");
        if (title.equals(CertificateType.CERT_TITLE_USER)) {
      // check if it is self-signed
          if (certChain.length == 1) {
            //System.out.println("adding: " + dname);
            profilePanel.requestlist.addElement(dname);
          }
        }
      }
      profilePanel.requestBox.updateUI();
    }
    else {
      log.warn("Unable to get aliases as Certificate cache Service is null");
    }
    } catch (KeyStoreException kex) {}
  
  }

  public boolean generateUserCertRequest() {
    String pwd1 = new String(getPwd());
    String pwd2 = new String(pwdPanel.jPasswordField2.getPassword());
    if (!pwd1.equals(pwd2)) {
      JOptionPane.showMessageDialog(null, "Password does not match.");
      return false;
    }

    String userdn = getUserDN();
    X500Name userx500 = null;
    try {
      userx500 = new X500Name(userdn);
    } catch (IOException ex) {
      JOptionPane.showMessageDialog(null, "Cannot create X500Name: " + userdn);
      return false;
    }
    java.util.List list = keyRing.findCert(userx500);
    if (list != null && list.size() != 0) {
      JOptionPane.showMessageDialog(null, "Certificate already exists.");
      return false;
    }

    keyRing.checkOrMakeCert(userx500, false);

    if (!setKeyPassword(userx500, getPwd())) {
      JOptionPane.showMessageDialog(null, "User certificate not received, either request failed or pending.");
      return false;
    }

    JOptionPane.showMessageDialog(null, "Successfully generated user certificate.");
    return true;
  }

  /**
   * set password for a specific key, for user
   * There should be only one entry with the same dname for user,
   * otherwise this would create confusion of which keypass to set
   */
  public boolean setKeyPassword(X500Name dname, char [] pwd) {
    java.util.List list = keyRing.findPrivateKey(dname);
    // KeyStore keystore = keyRing.getKeyStore();
    if (list == null || list.size() == 0)
      return false;

    // not required to set password
    if (pwd.length == 0)
      return true;

    PrivateKeyCert keyCert = (PrivateKeyCert)list.get(0);
    PrivateKey privatekey = keyCert.getPrivateKey();
    CertificateStatus cs = keyCert.getCertificateStatus();
    String alias = cs.getCertificateAlias();
     CertificateCacheService cacheservice=(CertificateCacheService)
      serviceBroker.getService(this,
			       CertificateCacheService.class,
			       null);

  if(cacheservice==null) {
    log.warn("Unable to get Certificate cache Service in setKeyPassword");
  }
    try {
      java.security.cert.Certificate [] certChain =null;
      if(cacheservice!=null) {
        certChain=cacheservice.getCertificateChain(alias);
	cacheservice.setKeyEntry(alias, privatekey, pwd, certChain);
      }
      else {
	 return false;
      }
    } catch (KeyStoreException kex) {
      System.out.println("KeyStoreException: " + kex);
      return false;
    }
    return true;
  }

  public String getUserDN() {
    String dn = "cn=" + profilePanel.cnameField.getText()
      + ", ou=" + profilePanel.ouField.getText()
      + ",o=" + profilePanel.oField.getText()
      + ",l=" + profilePanel.lField.getText()
      + ",st=" + profilePanel.stField.getText()
      + ",c=" + profilePanel.cField.getText()
      + ",t=" + CertificateType.CERT_TITLE_USER;
    return dn;
  }

  private void processButtonEvent(ActionEvent evt) {
    if (evt.getSource() == nextButton) {
      if (generateUserCertRequest()) {
        isOk = true;
        this.dispose();
      }
      else {
        return;
      }
    }
    if (evt.getSource() == cancelButton) {
      isOk = false;
      this.dispose();
    }
  }

  private void processListEvent(ActionEvent evt) {
    if (evt.getSource() == profilePanel.requestBox) {
      String dname = (String)profilePanel.requestBox.getSelectedItem();
      if (dname != null) {
        try {
          X500Name userdn = new X500Name(dname);
          profilePanel.cnameField.setText(userdn.getCommonName());
          profilePanel.ouField.setText(userdn.getOrganizationalUnit());
          profilePanel.oField.setText(userdn.getOrganization());
          profilePanel.lField.setText(userdn.getLocality());
          profilePanel.stField.setText(userdn.getState());
          profilePanel.cField.setText(userdn.getCountry());
        } catch (IOException ioe) {}
      }
    }
  }

  private void jbInit() throws Exception {
    this.getContentPane().setLayout(borderLayout1);
    nextButton.setText("OK");
    cancelButton.setText("Cancel");
    this.getContentPane().add(buttonPanel,  BorderLayout.SOUTH);
    buttonPanel.add(nextButton, null);
    buttonPanel.add(cancelButton, null);
    this.getContentPane().add(jTabbedPane1,  BorderLayout.CENTER);

    profilePanel = new UserProfilePanel();
    pwdPanel = new PasswordPanel();

    jTabbedPane1.add(profilePanel, "Profile");
    jTabbedPane1.add(pwdPanel, "Password");
  }
}
