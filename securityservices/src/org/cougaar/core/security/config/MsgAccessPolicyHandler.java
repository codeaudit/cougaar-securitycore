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


package org.cougaar.core.security.config;

import java.util.Vector;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.AccessControlPolicy;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

public class MsgAccessPolicyHandler
  extends BaseConfigHandler
{
  private AccessControlPolicy acp;
  private String msgAction;
  private String critLevel;
  private String actionParty;
  private String agtAction;
  private String filterParty;
  private Vector verbs = null;
  private String msgParty;
  private String integrity;
  private String critParty;
  private String criticality;

  private String actionCom;
  private String agtActionCom;
  private String filterCom;
  private Vector verbsCom = null;
  private String msgCom;
  private String integrityCom;
  private String critCom;
  private String criticalityCom;
  
  public MsgAccessPolicyHandler(ServiceBroker sb) {
    super(sb);
  }
  
  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String topLevelTag) {
    
    acp = new AccessControlPolicy();
    currentSecurityPolicy = acp;
    super.collectPolicy(parser, parent, topLevelTag);
  }
  
  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr )
    throws SAXException {
    super.startElement(namespaceURI, localName, qName, attr);

    if (localName.equals("MessageAction")) {
      critLevel = "";
      msgAction = "";
    }
    
    if (localName.equals("AgentAction")) {
      actionParty = "";
      agtAction = "";
    }

    if (localName.equals("VerbFilter")) {
      filterParty = "";
      verbs = new Vector();
    }

    if (localName.equals("MessageIntegrity")) {
      msgParty = "";
      integrity = "";
    }

    if (localName.equals("MessageCriticality")) {
      critParty = "";
      criticality = "";
    }

    if (localName.equals("ComAgentAction")) {
      actionCom = "";
      agtActionCom = "";
    }

    if (localName.equals("ComVerbFilter")) {
      filterCom = "";
      verbsCom = new Vector();
    }

    if (localName.equals("ComMessageIntegrity")) {
      msgCom = "";
      integrityCom = "";
    }

    if (localName.equals("ComMessageCriticality")) {
      critCom = "";
      criticalityCom = "";
    }
  }
  
  public void endElement( String namespaceURI,
			  String localName,
			  String qName )
    throws SAXException {
    super.endElement(namespaceURI, localName, qName);
    if (endElementAction == SKIP) {
      return;
    }

    if (localName.equals("Name")) {
      String value = getContents();
      acp.Name = value;
    }
    
    if (localName.equals("Type")) {
      String value = getContents();
      if(value.equalsIgnoreCase("AGENT")){
        acp.Type = AccessControlPolicy.AGENT;
      }else if(value.equalsIgnoreCase("COMMUNITY")){
        acp.Type = AccessControlPolicy.COMMUNITY;
      }else if(value.equalsIgnoreCase("SOCIETY")){
        acp.Type = AccessControlPolicy.SOCIETY;
      }else{
        if (log.isErrorEnabled()) {
          log.error("Access Control Policy Handler: unexpected Type value.");
        }
      }
    }
    
    if (localName.equals("Direction")) {
      String value = getContents();
      if(value.equalsIgnoreCase("BOTH")){
        acp.Direction = AccessControlPolicy.BOTH;
      }else if(value.equalsIgnoreCase("INCOMING")){
        acp.Direction = AccessControlPolicy.INCOMING;
      }else if(value.equalsIgnoreCase("OUTGOING")){
        acp.Direction = AccessControlPolicy.OUTGOING;
      }else{
        if (log.isErrorEnabled()) {
          log.error("Access Control Policy Handler: unexpected Direction value.");
        }
      }
    }

    if (localName.equals("CriticalityLevel")) {
      critLevel = getContents();
    }
    if (localName.equals("MsgAction")) {
      msgAction = getContents();
    }
    if (localName.equals("MessageAction")) {
      acp.setMsgAction(critLevel, msgAction);
    }

    if (localName.equals("ActionParty")) {
      actionParty = getContents();
    }
    if (localName.equals("Action")) {
      agtAction = getContents();
    }
    if (localName.equals("AgentAction")) {
      acp.setAgentAction(actionParty, agtAction);
    }
    
    if (localName.equals("FilterParty")) {
      filterParty = getContents();
    }
    if (localName.equals("Verb")) {
      String value = getContents();
      verbs.add(value);
    }
    if (localName.equals("VerbFilter")) {
      acp.setVerbs(filterParty, verbs);
    }

    if (localName.equals("MsgParty")) {
      msgParty = getContents();
    }
    if (localName.equals("Integrity")) {
      integrity = getContents();
    }
    if (localName.equals("MessageIntegrity")) {
      acp.setIntegrity(msgParty, integrity);
    }

    if (localName.equals("CritParty")) {
      critParty = getContents();
    }
    if (localName.equals("Criticality")) {
      criticality = getContents();
    }
    if (localName.equals("MessageCriticality")) {
      acp.setCriticality(critParty, criticality);
    }

    //for community
    if (localName.equals("ActionCommunity")) {
      actionCom = getContents();
    }
    if (localName.equals("ComAction")) {
      agtActionCom = getContents();
    }
    if (localName.equals("ComAgentAction")) {
      acp.setComAgentAction(actionCom, agtActionCom);
    }
    
    if (localName.equals("FilterCommunity")) {
      filterCom = getContents();
    }
    if (localName.equals("ComVerb")) {
      String value = getContents();
      verbsCom.add(value);
    }
    if (localName.equals("ComVerbFilter")) {
      acp.setComVerbs(filterCom, verbsCom);
    }

    if (localName.equals("MsgCommunity")) {
      msgCom = getContents();
    }
    if (localName.equals("ComIntegrity")) {
      integrityCom = getContents();
    }
    if (localName.equals("ComMessageIntegrity")) {
      acp.setComIntegrity(msgCom, integrityCom);
    }

    if (localName.equals("CritCommunity")) {
      critCom = getContents();
    }
    if (localName.equals("ComCriticality")) {
      criticalityCom = getContents();
    }
    if (localName.equals("ComMessageCriticality")) {
      acp.setComCriticality(critCom, criticalityCom);
    }
    
    // Reset contents
    writerReset();
  }
}
