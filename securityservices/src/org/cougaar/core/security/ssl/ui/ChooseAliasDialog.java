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

import org.cougaar.core.security.util.UIUtil;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.border.Border;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;


public class ChooseAliasDialog extends JDialog {
  private Vector aliases = new Vector();

  JPanel buttonPanel = new JPanel();
  JPanel searchPanel = new JPanel();
  JButton okButton = new JButton();
  BorderLayout borderLayout1 = new BorderLayout();
  Border border1;
  Border border2;
  TitledBorder titledBorder2;
  JTextArea selectionText = new JTextArea();
  JPanel certPanel = new JPanel();
  GridLayout gridLayout1 = new GridLayout(1, 2);
  JTextArea detailText = new JTextArea();
  JList aliasList = new JList(aliases);
  Border border3;
  TitledBorder titledBorder1;
  Border border4;

  public ChooseAliasDialog() {
    super((Frame)null, "Select certificate", true);
    try {
      jbInit();
    }
    catch(Exception e) {
      e.printStackTrace();
    }
  }

  private void jbInit() throws Exception {
    border1 = BorderFactory.createEmptyBorder(5,10,5,10);
    border2 = BorderFactory.createCompoundBorder(new EtchedBorder(EtchedBorder.RAISED,Color.white,new Color(142, 142, 142)),BorderFactory.createEmptyBorder(10,20,10,20));
    titledBorder2 = new TitledBorder(BorderFactory.createMatteBorder(10,20,10,20,Color.white),"");
    border3 = new EtchedBorder(EtchedBorder.RAISED,Color.white,new Color(142, 142, 142));
    titledBorder1 = new TitledBorder(border3,"Certificate Detail:");
    border4 = BorderFactory.createCompoundBorder(titledBorder1,BorderFactory.createEmptyBorder(10,20,10,20));
    okButton.setText("OK");
    searchPanel.setLayout(borderLayout1);
    selectionText.setBorder(border1);
    selectionText.setText("Please select the certificate to be used to connect to the remote " +
    "site:");
    selectionText.setLineWrap(true);
    selectionText.setWrapStyleWord(true);
    certPanel.setLayout(gridLayout1);

    aliasList.setBackground(Color.lightGray);
    aliasList.setBorder(titledBorder2);
    aliasList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    aliasList.addListSelectionListener(new ListSelectionListener() {
      public void valueChanged(ListSelectionEvent e) {
        handleItemEvent();
      }
    });

    detailText.setBorder(border4);
    detailText.setPreferredSize(new Dimension(100, 50));
    detailText.setText("");
    detailText.setLineWrap(true);
    detailText.setWrapStyleWord(true);
    detailText.setEditable(false);
    certPanel.setBorder(BorderFactory.createEtchedBorder());
    this.getContentPane().add(buttonPanel,  BorderLayout.SOUTH);
    this.getContentPane().add(searchPanel,  BorderLayout.CENTER);
    buttonPanel.add(okButton, null);
    searchPanel.add(selectionText,  BorderLayout.NORTH);
    searchPanel.add(certPanel,  BorderLayout.CENTER);
    certPanel.add(aliasList, null);
    certPanel.add(detailText, null);

    okButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        handleButtonEvent();
      }
    });

    setSize(300, 200);
    UIUtil.centerWindow(this);
  }

  private void handleItemEvent() {
    String alias = getSelection();
    if (alias != null) {
      try {
        X509Certificate certimpl = (X509Certificate)
          aliasTable.get(alias);
        if (certimpl != null) {
          detailText.setText(printCertificateDetails(certimpl));
        }
      } catch (Exception e) {}
    }
  }

  private void handleButtonEvent() {
    dispose();
  }

  public void setList(Hashtable list) {
    aliases.capacity();
    for (Enumeration e = list.keys(); e.hasMoreElements(); ) {
      String alias = (String)e.nextElement();
      aliases.addElement(alias);
    }
    aliasList.updateUI();

    aliasTable = list;
  }

  public String getSelection() {
    return (String)aliasList.getSelectedValue();
  }

  public static void main(String [] argv) {
    ChooseAliasDialog ui = new ChooseAliasDialog();
    ui.show();
  }

  public static String printCertificateDetails(X509Certificate  certimpl) {
    StringBuffer strbuf = new StringBuffer();
    strbuf.append("Version : "
		+certimpl.getVersion());
    strbuf.append("\n");
    strbuf.append("Subject : "
		+certimpl.getSubjectDN().getName());
    strbuf.append("\n");
    strbuf.append("Signature Algorithm : "
		+certimpl.getSigAlgName()
		+" : "+certimpl.getSigAlgOID());
    strbuf.append("\n");
    strbuf.append("Validity :");
    strbuf.append("\n");
    strbuf.append("From :"
		+certimpl.getNotBefore().toString());
    strbuf.append("\n");
    strbuf.append("To :"
		+certimpl.getNotAfter().toString());
    strbuf.append("\n");
    strbuf.append("Issuer : "
		+certimpl.getIssuerDN().getName());
    strbuf.append("\n");
    strbuf.append("Serial No : "
		+certimpl.getSerialNumber());
    strbuf.append("\n");

    strbuf.append("Algorithm : "
		+certimpl.getPublicKey().getAlgorithm());
    return strbuf.toString();
  }


  private Hashtable aliasTable = new Hashtable();
}
