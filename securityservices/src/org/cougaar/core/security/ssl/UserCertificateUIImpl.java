package org.cougaar.core.security.ssl;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.border.*;

public class UserCertificateUIImpl extends JDialog implements UserCertificateUI {
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
  JList aliasList = new JList();
  Border border3;
  TitledBorder titledBorder1;
  Border border4;

  public UserCertificateUIImpl() {
    super((Frame)null, "Select certificate", true);
    try {
      jbInit();
    }
    catch(Exception e) {
      e.printStackTrace();
    }
  }

  public String chooseClientAlias(String serveralias,
                            String serverhost,
                            String serverport) {
    // get certificates from keystore


    show();

    // get selected alias
    return (String)aliasList.getSelectedValue();
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
    detailText.setBorder(border4);
    detailText.setPreferredSize(new Dimension(100, 50));
    detailText.setText("");
    detailText.setLineWrap(true);
    detailText.setWrapStyleWord(true);
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
  }

  private void handleButtonEvent() {
    dispose();
  }

  public static void main(String [] argv) {
    UserCertificateUIImpl ui = new UserCertificateUIImpl();
    ui.show();
  }
}