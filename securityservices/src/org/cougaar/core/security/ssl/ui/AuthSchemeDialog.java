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
package org.cougaar.core.security.ssl.ui;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.userauth.ui.UserCertRequestDialog;
import org.cougaar.core.security.util.UIUtil;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.border.Border;


public class AuthSchemeDialog
  extends JDialog
{
  BorderLayout borderLayout1 = new BorderLayout();
  JPanel jPanel2 = new JPanel();
  JPanel jPanel3 = new JPanel();
  JButton cancelButton = new JButton();
  JButton okButton = new JButton();
  JButton createCertButton = new JButton();
  JTextArea jTextArea1 = new JTextArea();
  BorderLayout borderLayout2 = new BorderLayout();

  Vector authHandlers = new Vector();

  ServiceBroker serviceBroker;

  public AuthSchemeDialog(ServiceBroker sb) {
    super((Frame)null, "Select Authenticate Scheme", true);

    serviceBroker = sb;
    try {
      jbInit();
    }
    catch(Exception e) {
      e.printStackTrace();
    }
  }
  private void jbInit() throws Exception {
    border1 = BorderFactory.createEmptyBorder(10,20,10,20);
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

    createCertButton.setText("Request Identitty");
    if (serviceBroker == null)
      createCertButton.setEnabled(false);
    createCertButton.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(ActionEvent e) {
        createCertButton_actionPerformed(e);
      }
    });

    jTextArea1.setEditable(false);
    jTextArea1.setText("\n    Please select authentication schemes.");
    jTextArea1.setLineWrap(true);
    jTextArea1.setWrapStyleWord(true);
    jPanel3.setLayout(borderLayout2);
    jPanel3.setPreferredSize(new Dimension(68, 60));
    jPanel1.setLayout(borderLayout3);
    handlerList.setBackground(Color.pink);
    handlerList.setBorder(BorderFactory.createEtchedBorder());
    jPanel1.setBorder(border1);
    this.getContentPane().add(jPanel2, BorderLayout.SOUTH);
    jPanel2.add(okButton, null);
    jPanel2.add(cancelButton, null);
    jPanel2.add(createCertButton, null);
    this.getContentPane().add(jPanel3, BorderLayout.NORTH);
    jPanel3.add(jTextArea1, BorderLayout.CENTER);
    this.getContentPane().add(jPanel1, BorderLayout.CENTER);
    jPanel1.add(handlerList,  BorderLayout.CENTER);

    setSize(300, 300);

    UIUtil.centerWindow(this);
  }

  public boolean showDialog() {
    show();
    return isOk;
  }

  public void setHandlers(Vector handlers) {
    authHandlers.removeAllElements();
    authHandlers.addAll(handlers);
    handlerList.updateUI();
  }

  public Vector getSelection() {
    Vector selection = new Vector();
    Object [] values = handlerList.getSelectedValues();
    for (int i = 0; i < values.length; i++) {
      //System.out.println("selected: " + i + " : " + handlerList.isSelectedIndex(i));
      if (handlerList.isSelectedIndex(i))
       selection.addElement(values[i]);
    }
    return selection;
  }

  boolean isOk = false;
  JPanel jPanel1 = new JPanel();
  JList handlerList = new JList(authHandlers);
  BorderLayout borderLayout3 = new BorderLayout();
  Border border1;

  void okButton_actionPerformed(ActionEvent e) {
    isOk =true;
    this.dispose();
  }

  void cancelButton_actionPerformed(ActionEvent e) {
    this.dispose();
  }

  void createCertButton_actionPerformed(ActionEvent e) {
    // and send request to CA.
    UserCertRequestDialog dialog = new UserCertRequestDialog(serviceBroker);
    dialog.showDialog();
  }

}
