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

package org.cougaar.core.security.test.crypto;

import java.util.*;
import java.awt.event.*;
import java.awt.*;
import javax.swing.*;

// Cougaar core services
import org.cougaar.core.node.*;
import org.cougaar.core.agent.*;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.core.mts.*;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.domain.RootFactory;

// Cougaar overlay
import org.cougaar.core.service.identity.*;

public class AgMobPlugin extends org.cougaar.core.plugin.SimplePlugin 
{
  private static final String moveCryptoVerb = "MoveCrypto";

  private AgentIdentityService aiService;
  private NodeIdentifier thisNodeID;
  private NodeIdentifier toNodeID;
  private ClusterIdentifier thisAgentID;
  private String targetNode;

  private MessageTransportService mts;
  private MessageTransportClient mtc;

  /** The name of the window */
  private String frame_label;
  private ActionListener button_listener;
  private String button_label;

  // Swing components
  private JTextField textField;
  private JButton button;

  public void setupSubscriptions()
  {
    // get our agent's ID
    thisAgentID = getBindingSite().getAgentIdentifier();

    // get the nodeID service          
    NodeIdentificationService nodeService = (NodeIdentificationService) 
      getBindingSite().getServiceBroker().getService(
          this, 
          NodeIdentificationService.class,
          null);

    thisNodeID = ((nodeService != null) ? 
		  nodeService.getNodeIdentifier() :
		  null);

    String paramOrigNode = thisNodeID.toAddress();

    // Get agent mobility service
    aiService = (AgentIdentityService)
      getBindingSite().getServiceBroker().getService(
	this, 
	AgentIdentityService.class,
	null);

    button_listener = new ActionListener() {
	public void actionPerformed(ActionEvent e) {

	  targetNode = textField.getText();
	  // parse the destination node ID
	  toNodeID = new NodeIdentifier(targetNode);
	  System.out.println("Setting target Node to " + targetNode);

	  if (targetNode != null) {
	    try {
	      initiateTransfer();
	    }
	    catch (Exception ex) {
	      System.out.println("ERROR: " + ex);
	      ex.printStackTrace();
	    }
	  }
	  else {
	    System.out.println("Target agent not specified");
	  }
	}
      };

    initTransport();
    frame_label = "Agent mobility test" + thisNodeID.toAddress()
      + "/" + thisAgentID.toAddress();
    button_label = "Bundle keys";
    createGUI();
  }

  private void initiateTransfer() {
    TransferableIdentity ti =
      aiService.transferTo(toNodeID);

    // create the move-message
    /* as of 9.4.0, this cannot be used. I've removed it instead of
     * trying to fix it since it is only test code. -- gmount
    MoveCryptoMessage moveMsg = 
      new MoveCryptoMessage(
	thisNodeID,
	toNodeID,
	ti);
    mts.sendMessage(moveMsg);
    */
  }

  public void execute()
  {
  }

  private void completeTransfer(Message msg) {
    System.out.println("Received a message: " + msg.getClass().getName());
    /* as of 9.4.0, this cannot be used. I've removed it instead of
     * trying to fix it since it is only test code. -- gmount
    if (msg instanceof MoveCryptoMessage) {
      String source = msg.getOriginator().toAddress();
      String target = msg.getTarget().toAddress();
      MoveCryptoMessage m = (MoveCryptoMessage) msg;
      System.out.println("Received Transferable identity from "
			 + source + " to " + target);
      try {
	aiService.acquire(m.getTransferableIdentity());
      }
      catch (Exception e) {
	System.out.println("Error: " + e);
	e.printStackTrace();
      }
    }
    */
  }

  /**
   * Create a simple free-floating GUI button with a label
   */
  private void createGUI()
  {
    JFrame frame = new JFrame(frame_label);
    frame.getContentPane().setLayout(new FlowLayout());

    JPanel labelPane = new JPanel();
    labelPane.setLayout(new GridLayout(0, 1));
    JLabel targetLabel = new JLabel("Target Node ");
    labelPane.add(targetLabel);
    JLabel buttonLabel = new JLabel("");
    labelPane.add(buttonLabel);

    // Layout the text fields in a panel
    JPanel fieldPane = new JPanel();
    fieldPane.setLayout(new GridLayout(0, 1));

    // Create the button
    button = new JButton(button_label);
    textField = new JTextField(30);

    // Register a listener for the button
    button.addActionListener(button_listener);
    //textField.addActionListener(text_listener);

    fieldPane.add(textField);
    fieldPane.add(button);

    //Put the panels in another panel, labels on left,
    //text fields on right
    JPanel contentPane = new JPanel();
    contentPane.setBorder(BorderFactory.createEmptyBorder(20, 20,
                                                      20, 20));
    contentPane.setLayout(new BorderLayout());
    contentPane.add(labelPane, BorderLayout.CENTER);
    contentPane.add(fieldPane, BorderLayout.EAST);

    frame.getContentPane().add("Center", contentPane);
    frame.pack();
    frame.setVisible(true);
  }

  private void initTransport() {
    // create a dummy message transport client
    mtc = new MessageTransportClient() {
        public void receiveMessage(Message message) {
	  completeTransfer(message);
        }
        public MessageAddress getMessageAddress() {
          return thisAgentID;
        }
      };

    // get the message transport
    mts = (MessageTransportService) 
      getBindingSite().getServiceBroker().getService(
	mtc,   // simulated client 
	MessageTransportService.class,
	null);
    if (mts == null) {
      System.out.println(
	"Unable to get message transport service");
    }
  }

}
