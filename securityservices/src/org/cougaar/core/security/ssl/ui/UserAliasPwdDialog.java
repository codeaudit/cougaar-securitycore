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
package org.cougaar.core.security.ssl.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import org.cougaar.core.security.util.UIUtil;

public class UserAliasPwdDialog extends JDialog {
  BorderLayout borderLayout1 = new BorderLayout();
  JPanel jPanel1 = new JPanel();
  JPanel jPanel2 = new JPanel();
  JPanel jPanel3 = new JPanel();
  JButton cancelButton = new JButton();
  JButton okButton = new JButton();
  JTextArea jTextArea1 = new JTextArea();
  BorderLayout borderLayout2 = new BorderLayout();
  BorderLayout borderLayout3 = new BorderLayout();
  GridLayout gridLayout1 = new GridLayout();
  JPanel jPanel4 = new JPanel();
  JPanel jPanel5 = new JPanel();
  GridLayout gridLayout2 = new GridLayout();
  GridLayout gridLayout3 = new GridLayout();
  JPanel jPanel6 = new JPanel();
  JPanel jPanel7 = new JPanel();
  JLabel jLabel1 = new JLabel();
  JPanel jPanel8 = new JPanel();
  JPanel jPanel9 = new JPanel();
  JLabel jLabel2 = new JLabel();
  JPanel jPanel10 = new JPanel();
  JPanel jPanel11 = new JPanel();
  JPanel jPanel12 = new JPanel();
  JPanel jPanel13 = new JPanel();
  JPasswordField pwdField = new JPasswordField();
  JTextField aliasField = new JTextField();

  public UserAliasPwdDialog() {
    super((Frame)null, "User authentication", true);

    try {
      jbInit();
    }
    catch(Exception e) {
      e.printStackTrace();
    }
  }

  public void setPrompt(String text) {
    jTextArea1.setText(text);
  }

  private void jbInit() throws Exception {
    this.getContentPane().setLayout(borderLayout1);
    cancelButton.setText("Cancel");
    cancelButton.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(ActionEvent e) {
        cancelButton_actionPerformed(e);
      }
    });
    okButton.setText("OK");
    okButton.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(ActionEvent e) {
        okButton_actionPerformed(e);
      }
    });
    jTextArea1.setText("\nPlease enter alias for user certificate and the password to unlock " +
    "the user certificate from local keystore.");
    jTextArea1.setLineWrap(true);
    jTextArea1.setWrapStyleWord(true);
    jTextArea1.setEditable(false);
    jPanel3.setLayout(borderLayout2);
    jPanel3.setPreferredSize(new Dimension(68, 60));
    jPanel1.setBorder(BorderFactory.createLineBorder(Color.black));
    jPanel1.setLayout(gridLayout1);
    jPanel5.setLayout(gridLayout2);
    jPanel4.setLayout(gridLayout3);
    gridLayout2.setRows(6);
    gridLayout3.setRows(6);
    jLabel1.setText("User alias:");
    jLabel2.setText("Password:");
    pwdField.setMinimumSize(new Dimension(120, 21));
    pwdField.setPreferredSize(new Dimension(120, 21));
    aliasField.setPreferredSize(new Dimension(120, 21));
    aliasField.setMinimumSize(new Dimension(120, 21));
    aliasLabel.setText("Alias list:");
    aliaslistBox.setPreferredSize(new Dimension(130, 22));
    aliaslistBox.setMinimumSize(new Dimension(120, 21));
    aliaslistBox.setMaximumSize(new Dimension(130, 22));
    aliaslistBox.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(ActionEvent e) {
        aliaslistBox_actionPerformed(e);
      }
    });
    jLabel3.setText("Host:");
    hostField.setMinimumSize(new Dimension(120, 21));
    hostField.setPreferredSize(new Dimension(120, 21));
    hostField.setEditable(false);
    cacheBox.setText("cache credential");
    this.getContentPane().add(jPanel1, BorderLayout.CENTER);
    jPanel1.add(jPanel5, null);
    jPanel5.add(jPanel6, null);
    jPanel5.add(jPanel14, null);
    jPanel14.add(jLabel3, null);
    jPanel9.add(jLabel1, null);
    jPanel5.add(jPanel8, null);
    jPanel8.add(aliasLabel, null);
    jPanel5.add(jPanel9, null);
    jPanel5.add(jPanel7, null);
    jPanel7.add(jLabel2, null);
    jPanel1.add(jPanel4, null);
    jPanel4.add(jPanel10, null);
    jPanel4.add(jPanel15, null);
    jPanel15.add(hostField, null);
    jPanel4.add(jPanel12, null);
    jPanel12.add(aliaslistBox, null);
    jPanel4.add(jPanel11, null);
    jPanel11.add(aliasField, null);
    jPanel4.add(jPanel13, null);
    jPanel13.add(pwdField, null);
    this.getContentPane().add(jPanel2, BorderLayout.SOUTH);
    jPanel2.setLayout(borderLayout3);
    jPanel2.add(jPanel16, BorderLayout.CENTER);
    jPanel16.add(cacheBox, null);
    jPanel2.add(jPanel17, BorderLayout.SOUTH);
    jPanel17.add(okButton, null);
    jPanel17.add(cancelButton, null);
    this.getContentPane().add(jPanel3, BorderLayout.NORTH);
    jPanel3.add(jTextArea1, BorderLayout.CENTER);
    cacheBox.setVisible(false);

    setSize(300, 400);
    UIUtil.centerWindow(this);
  }

  public boolean showDialog() {
    setVisible(true);
    return isOk;
  }

  public void setAlias(String alias) {
    aliasField.setText(alias);
  }

  public String getAlias() {
    return aliasField.getText();
  }

  public void setHost(String host) {
    hostField.setText(host);
  }

  public char[] getPwd() {
    return pwdField.getPassword();
  }

  public boolean isCached() {
    return cacheBox.isSelected();
  }

  public void setAliasList(ArrayList list) {
    aliaslist.addAll(list);
    aliaslistBox.updateUI();
  }

  // this is for BASIC authentication
  public void hideLookup() {
    aliasLabel.setVisible(false);
    aliaslistBox.setVisible(false);
    cacheBox.setVisible(true);
  }

  boolean isOk = false;
  Vector aliaslist = new Vector();
  JLabel aliasLabel = new JLabel();
  JComboBox aliaslistBox = new JComboBox(aliaslist);
  JPanel jPanel14 = new JPanel();
  JPanel jPanel15 = new JPanel();
  JPanel jPanel16 = new JPanel();
  JPanel jPanel17 = new JPanel();
  JLabel jLabel3 = new JLabel();
  JTextField hostField = new JTextField();
  JCheckBox cacheBox = new JCheckBox();

  void okButton_actionPerformed(ActionEvent e) {
    isOk =true;
    this.dispose();
  }

  void cancelButton_actionPerformed(ActionEvent e) {
    this.dispose();
  }

  void aliaslistBox_actionPerformed(ActionEvent e) {
    int index = aliaslistBox.getSelectedIndex();
    if (index >= 0) {
      String aliasString = (String)aliaslist.get(index);
      String alias = aliasString.substring(0, aliasString.indexOf(" ("));
      aliasField.setText(alias);
    }
  }
}
