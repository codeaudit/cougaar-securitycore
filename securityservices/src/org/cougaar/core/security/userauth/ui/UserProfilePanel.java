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


public class UserProfilePanel extends JPanel {
  Vector dnlist = new Vector();

  GridLayout gridLayout1 = new GridLayout();
  JLabel jLabel1 = new JLabel();
  JPanel ouPanel = new JPanel();
  GridLayout gridLayout2 = new GridLayout();
  JLabel jLabel2 = new JLabel();
  JTextField ouField = new JTextField();
  GridLayout gridLayout3 = new GridLayout();
  JPanel cnamePanel = new JPanel();
  JTextField cnameField = new JTextField();
  JLabel jLabel3 = new JLabel();
  GridLayout gridLayout4 = new GridLayout();
  JPanel oPanel = new JPanel();
  JTextField oField = new JTextField();
  JLabel jLabel4 = new JLabel();
  JPanel lPanel = new JPanel();
  JTextField lField = new JTextField();
  JLabel jLabel5 = new JLabel();
  GridLayout gridLayout5 = new GridLayout();
  JPanel stPanel = new JPanel();
  JTextField stField = new JTextField();
  JLabel jLabel6 = new JLabel();
  GridLayout gridLayout6 = new GridLayout();
  JPanel cPanel = new JPanel();
  JTextField cField = new JTextField();
  JLabel jLabel7 = new JLabel();
  GridLayout gridLayout7 = new GridLayout();
  JPanel cadnPanel = new JPanel();
  FlowLayout flowLayout1 = new FlowLayout();
  JLabel jLabel8 = new JLabel();
  JComboBox cadnBox = new JComboBox(dnlist);

  public UserProfilePanel() {
    try {
      jbInit();
    }
    catch(Exception e) {
      e.printStackTrace();
    }
  }
  private void jbInit() throws Exception {
    jLabel1.setText("User X.509 Attributes");
    gridLayout1.setColumns(2);
    gridLayout1.setRows(10);
    this.setLayout(gridLayout1);
    ouPanel.setLayout(gridLayout2);
    gridLayout2.setColumns(2);
    jLabel2.setText("Organization unit:");
    ouField.setPreferredSize(new Dimension(100, 21));
    gridLayout3.setColumns(2);
    cnamePanel.setLayout(gridLayout3);
    cnameField.setPreferredSize(new Dimension(100, 21));
    jLabel3.setText("Common Name:");
    gridLayout4.setColumns(2);
    oPanel.setLayout(gridLayout4);
    oField.setPreferredSize(new Dimension(100, 21));
    jLabel4.setText("Organization:");
    lPanel.setLayout(gridLayout5);
    lField.setPreferredSize(new Dimension(100, 21));
    jLabel5.setText("Locality:");
    gridLayout5.setColumns(2);
    stPanel.setLayout(gridLayout6);
    stField.setPreferredSize(new Dimension(100, 21));
    jLabel6.setText("State:");
    gridLayout6.setColumns(2);
    cPanel.setLayout(gridLayout7);
    cField.setPreferredSize(new Dimension(100, 21));
    jLabel7.setText("Country:");
    gridLayout7.setColumns(2);
    cadnPanel.setLayout(flowLayout1);
    jLabel8.setText("Select CA:");
    flowLayout1.setAlignment(FlowLayout.LEFT);
    this.add(jLabel1, null);
    this.add(cadnPanel, null);
    cPanel.add(jLabel7, null);
    cPanel.add(cField, null);
    stPanel.add(jLabel6, null);
    stPanel.add(stField, null);
    lPanel.add(jLabel5, null);
    lPanel.add(lField, null);
    oPanel.add(jLabel4, null);
    oPanel.add(oField, null);
    cnamePanel.add(jLabel3, null);
    cnamePanel.add(cnameField, null);
    ouPanel.add(jLabel2, null);
    ouPanel.add(ouField, null);
    cadnPanel.add(jLabel8, null);
    cadnPanel.add(cadnBox, null);

    this.add(cnamePanel, null);
    this.add(ouPanel, null);
    this.add(oPanel, null);
    this.add(lPanel, null);
    this.add(stPanel, null);
    this.add(cPanel, null);

    cadnPanel.setVisible(false);
  }
}