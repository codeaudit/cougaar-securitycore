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

import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.Vector;

import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;


public class UserProfilePanel extends JPanel {
  Vector dnlist = new Vector();
  Vector requestlist = new Vector();

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
  GridLayout gridLayout9 = new GridLayout();
  JLabel jLabel8 = new JLabel();
  JComboBox cadnBox = new JComboBox(dnlist);
  JPanel oldcertPanel = new JPanel();
  JLabel jLabel9 = new JLabel();
  GridLayout gridLayout8 = new GridLayout();
  JComboBox requestBox = new JComboBox(requestlist);

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
    cadnPanel.setLayout(gridLayout9);
    gridLayout9.setColumns(2);
    jLabel8.setText("Select CA:");
    oldcertPanel.setLayout(gridLayout8);
    gridLayout8.setColumns(2);
    jLabel9.setText("Old request:");
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
    oldcertPanel.add(jLabel9, null);
    oldcertPanel.add(requestBox, null);
    cadnPanel.add(jLabel8, null);
    cadnPanel.add(cadnBox, null);
    this.add(oldcertPanel, null);

    this.add(cnamePanel, null);
    this.add(ouPanel, null);
    this.add(oPanel, null);
    this.add(lPanel, null);
    this.add(stPanel, null);
    this.add(cPanel, null);

    cadnPanel.setVisible(false);
  }
}
