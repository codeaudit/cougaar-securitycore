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

public class PasswordPanel extends JPanel {
  GridLayout gridLayout1 = new GridLayout();
  JPanel jPanel1 = new JPanel();
  JPanel jPanel2 = new JPanel();
  JPanel jPanel3 = new JPanel();
  JPanel jPanel4 = new JPanel();
  GridLayout gridLayout2 = new GridLayout();
  JLabel jLabel1 = new JLabel();
  JPasswordField jPasswordField1 = new JPasswordField();
  JLabel jLabel2 = new JLabel();
  JPanel jPanel5 = new JPanel();
  GridLayout gridLayout3 = new GridLayout();
  JPasswordField jPasswordField2 = new JPasswordField();
  JLabel jLabel3 = new JLabel();

  public PasswordPanel() {
    try {
      jbInit();
    }
    catch(Exception e) {
      e.printStackTrace();
    }
  }
  private void jbInit() throws Exception {
    gridLayout1.setRows(10);
    this.setLayout(gridLayout1);
    jPanel4.setLayout(gridLayout2);
    gridLayout2.setColumns(2);
    jLabel1.setText("Key password:");
    jLabel2.setText("Password to protect your key.");
    jPasswordField1.setPreferredSize(new Dimension(100, 21));
    jPanel5.setLayout(gridLayout3);
    gridLayout3.setColumns(2);
    jPasswordField2.setPreferredSize(new Dimension(100, 21));
    jLabel3.setText("Verify password:");
    this.add(jPanel1, null);
    this.add(jPanel2, null);
    this.add(jPanel3, null);
    this.add(jPanel4, null);
    jPanel4.add(jLabel1, null);
    jPanel5.add(jLabel3, null);
    jPanel5.add(jPasswordField2, null);
    jPanel4.add(jPasswordField1, null);
    this.add(jPanel5, null);
    jPanel3.add(jLabel2, null);
  }
}
