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
package org.cougaar.core.security.userauth.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.border.*;

import java.util.*;
import java.io.*;

import java.security.*;
import java.security.cert.*;
import sun.security.x509.*;

import org.cougaar.core.component.*;

import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.util.UIUtil;

public class UserCertRequestDialog extends JDialog {
  BorderLayout borderLayout1 = new BorderLayout();
  JPanel buttonPanel = new JPanel();
  JButton nextButton = new JButton();
  JButton cancelButton = new JButton();
  JPanel panels[] = new JPanel[2];

  int panelIndex = 0;
  boolean isOk = false;

  ServiceBroker serviceBroker;
  JTabbedPane jTabbedPane1 = new JTabbedPane();

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

    try {
      jbInit();

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
  }

  private ActionListener createButtonListener() {
    return new ActionListener() {
      public void actionPerformed(ActionEvent evt) {
        processButtonEvent(evt);
      }
    };
  }

  public boolean showDialog() {
    show();
    return isOk;
  }

  private void setCaDNs(java.util.List caDNs) {
    UserProfilePanel profilePanel = (UserProfilePanel)panels[0];
    for (int i = 0; i < caDNs.size(); i++) {
      String cadn = (String)caDNs.get(i);
      profilePanel.dnlist.addElement(cadn);
    }
    profilePanel.cadnBox.updateUI();
    profilePanel.cadnBox.setSelectedIndex(0);
  }

  private String getCaDN() {
    UserProfilePanel profilePanel = (UserProfilePanel)panels[0];
    int index = profilePanel.cadnBox.getSelectedIndex();
    return (String)profilePanel.dnlist.get(index);
  }

  private char [] getPwd() {
    return ((PasswordPanel)panels[1]).jPasswordField1.getPassword();
  }

  public boolean generateUserCertRequest() {
    String pwd1 = new String(getPwd());
    String pwd2 = new String(((PasswordPanel)panels[1]).jPasswordField2.getPassword());
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

    keyRing.checkOrMakeCert(userx500);

    if (!setKeyPassword(userx500, getPwd())) {
      JOptionPane.showMessageDialog(null, "Failed to generate user certificate.");
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
    KeyStore keystore = keyRing.getKeyStore();
    if (list == null || list.size() == 0)
      return false;

    // not required to set password
    if (pwd.length == 0)
      return true;

    PrivateKeyCert keyCert = (PrivateKeyCert)list.get(0);
    PrivateKey privatekey = keyCert.getPrivateKey();
    CertificateStatus cs = keyCert.getCertificateStatus();
    String alias = cs.getCertificateAlias();
    try {
      java.security.cert.Certificate [] certChain =
        keystore.getCertificateChain(alias);
      keystore.setKeyEntry(alias, privatekey, pwd, certChain);
    } catch (KeyStoreException kex) {
      System.out.println("KeyStoreException: " + kex);
      return false;
    }
    return true;
  }

  public String getUserDN() {
    UserProfilePanel profilePanel = (UserProfilePanel)panels[0];
    String dn = "cn=" + profilePanel.cnameField.getText()
      + ", ou=" + profilePanel.ouField.getText()
      + ",o=" + profilePanel.cnameField.getText()
      + ",l=" + profilePanel.lField.getText()
      + ",st=" + profilePanel.stField.getText()
      + ",c=" + profilePanel.cField.getText()
      + ",t=" + DirectoryKeyStore.CERT_TITLE_USER;
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

  private void jbInit() throws Exception {
    this.getContentPane().setLayout(borderLayout1);
    nextButton.setText("OK");
    cancelButton.setText("Cancel");
    this.getContentPane().add(buttonPanel,  BorderLayout.SOUTH);
    buttonPanel.add(nextButton, null);
    buttonPanel.add(cancelButton, null);
    this.getContentPane().add(jTabbedPane1,  BorderLayout.CENTER);

    panels[0] = new UserProfilePanel();
    panels[1] = new PasswordPanel();

    jTabbedPane1.add(panels[0], "Profile");
    jTabbedPane1.add(panels[1], "Password");
  }
}