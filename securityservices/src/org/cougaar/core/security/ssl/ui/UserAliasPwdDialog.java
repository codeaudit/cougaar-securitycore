package org.cougaar.core.security.ssl.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

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
    this.getContentPane().add(jPanel1, BorderLayout.CENTER);
    jPanel1.add(jPanel5, null);
    jPanel5.add(jPanel6, null);
    jPanel5.add(jPanel9, null);
    jPanel9.add(jLabel1, null);
    jPanel5.add(jPanel8, null);
    jPanel5.add(jPanel7, null);
    jPanel7.add(jLabel2, null);
    jPanel1.add(jPanel4, null);
    jPanel4.add(jPanel10, null);
    jPanel4.add(jPanel11, null);
    jPanel11.add(aliasField, null);
    jPanel4.add(jPanel12, null);
    jPanel4.add(jPanel13, null);
    jPanel13.add(pwdField, null);
    this.getContentPane().add(jPanel2, BorderLayout.SOUTH);
    jPanel2.add(okButton, null);
    jPanel2.add(cancelButton, null);
    this.getContentPane().add(jPanel3, BorderLayout.NORTH);
    jPanel3.add(jTextArea1, BorderLayout.CENTER);

    setSize(300, 400);
    UIUtil.centerWindow(this);
  }

  public boolean showDialog() {
    show();
    return isOk;
  }

  public void setAlias(String alias) {
    aliasField.setText(alias);
  }

  public String getAlias() {
    return aliasField.getText();
  }

  public char[] getPwd() {
    return pwdField.getPassword();
  }

  boolean isOk = false;

  void okButton_actionPerformed(ActionEvent e) {
    isOk =true;
    this.dispose();
  }

  void cancelButton_actionPerformed(ActionEvent e) {
    this.dispose();
  }
}