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
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.ActionEvent;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.border.Border;

import org.cougaar.core.security.util.UIUtil;


public class RequestIdentity
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

  boolean isOk = false;
  JPanel jPanel1 = new JPanel();
  BorderLayout borderLayout3 = new BorderLayout();
  Border border1;

  public RequestIdentity() {
    super((Frame)null, "Request Identity", true);

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

    // Buttons
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

    jTextArea1.setEditable(false);
    jTextArea1.setText("\n    Request certificate from CA");
    jTextArea1.setLineWrap(true);
    jTextArea1.setWrapStyleWord(true);
    jPanel3.setLayout(borderLayout2);
    jPanel3.setPreferredSize(new Dimension(68, 60));
    jPanel1.setLayout(borderLayout3);
    jPanel1.setBorder(border1);
    this.getContentPane().add(jPanel2, BorderLayout.SOUTH);
    jPanel2.add(okButton, null);
    jPanel2.add(cancelButton, null);
    jPanel2.add(createCertButton, null);
    this.getContentPane().add(jPanel3, BorderLayout.NORTH);
    jPanel3.add(jTextArea1, BorderLayout.CENTER);
    this.getContentPane().add(jPanel1, BorderLayout.CENTER);

    setSize(300, 300);

    UIUtil.centerWindow(this);
  }

  public boolean showDialog() {
    setVisible(true);
    return isOk;
  }

  void okButton_actionPerformed(ActionEvent e) {
    isOk =true;
    this.dispose();
  }

  void cancelButton_actionPerformed(ActionEvent e) {
    this.dispose();
  }

}
