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
 * Created on May 28, 2002, 5:48 PM
 */

package org.cougaar.core.security.config;

import org.xml.sax.*;
import org.xml.sax.helpers.*;
import java.util.Vector;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.util.*;

public class MsgAccessPolicyHandler
  extends BaseConfigHandler
{
  private AccessControlPolicy acp;
  private String critLevel;
  private String msgAction;
  private String actionParty;
  private String agtAction;
  private String filterParty;
  private Vector verbs = null;
  private String msgParty;
  private String integrity;
  private String critParty;
  private String criticality;
  
  public MsgAccessPolicyHandler(ServiceBroker sb) {
    super(sb);
  }
  
  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String role,
			    String topLevelTag) {
    
    acp = new AccessControlPolicy();
    currentSecurityPolicy = acp;
    super.collectPolicy(parser, parent, role, topLevelTag);
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

    if (localName.equals("ActionParty")) {
      actionParty = getContents();
    }
    if (localName.equals("Action")) {
      agtAction = getContents();
    }
    if (localName.equals("AgentAction")) {
      acp.setAgentAction(actionParty, agtAction);
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
    // Reset contents
    contents.reset();
  }
}
