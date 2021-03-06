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


package org.cougaar.core.security.test.crypto;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageTransportClient;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.core.service.identity.AgentIdentityService;
import org.cougaar.core.service.identity.TransferableIdentity;

public class AgMobPlugin extends org.cougaar.core.plugin.ComponentPlugin
{
  private static final String moveCryptoVerb = "MoveCrypto";

  private AgentIdentityService aiService;
  private MessageAddress thisNodeID;
  private MessageAddress toNodeID;
  private MessageAddress thisAgentID;
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

  protected void setupSubscriptions()
  {
    // get our agent's ID
    thisAgentID = getAgentIdentifier();

    // get the nodeID service          
    NodeIdentificationService nodeService = (NodeIdentificationService) 
      getBindingSite().getServiceBroker().getService(
          this, 
          NodeIdentificationService.class,
          null);

    thisNodeID = ((nodeService != null) ? 
		  nodeService.getMessageAddress() :
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
	  toNodeID = MessageAddress.getMessageAddress(targetNode);
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

  protected void execute()
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
        public long getIncarnationNumber() {
          return 0;
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
