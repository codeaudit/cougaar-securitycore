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

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

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
