/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */


package org.cougaar.core.security.monitoring.blackboard;
 
import java.util.List;
import java.util.ArrayList;
import java.util.ListIterator;
import java.io.Serializable;

import edu.jhuapl.idmef.XMLSerializable;
import edu.jhuapl.idmef.XMLUtils;


import org.cougaar.core.mts.MessageAddress;

import org.w3c.dom.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.apache.xml.serialize.*;


public class MRAgentLookUpReply implements XMLSerializable  {

  private  List AgentList=null;

  /**
   * Constructor for MRAgentLookUpReply
   * @param responseAgentList  List of AgentIdentifier
   */
  public MRAgentLookUpReply (List responseAgentList) {
    this.AgentList=responseAgentList;
  }
  
  public List getAgentList() {
    return this.AgentList;
  }
  
  private void setAgentList(List agentlist) {
    this.AgentList=agentlist;
  }
  
  /**Creates an object from the XML Node containing the XML version of this object.
     This method will look for the appropriate tags to fill in the fields. If it cannot find
     a tag for a particular field, it will remain null.
  */
  public MRAgentLookUpReply (Node node){
    //get userid nodes here
    NodeList children = node.getChildNodes();
    ArrayList agentListNodes = new ArrayList();
    for (int i=0; i<children.getLength(); i++){
      Node finger = children.item(i);
      if (finger.getNodeName().equals("AgentName")){
	String agentid=XMLUtils.getAssociatedString(finger);
	agentListNodes.add(MessageAddress.getMessageAddress(agentid));
      }
    }
    
  }
  public Node convertToXML(Document parent){

    Element agentLookUpReplyNode = parent.createElement("MRAgentLookUpReply");
    if (AgentList!= null){
      if(!AgentList.isEmpty()) {
	ListIterator iter=AgentList.listIterator();
	MessageAddress agentid=null;
	while(iter.hasNext()) {
	  agentid=(MessageAddress)iter.next();
	  Node agentNameNode = parent.createElement("AgentName");
	  agentNameNode.appendChild(parent.createTextNode(agentid.toString()));
	  agentLookUpReplyNode.appendChild(agentNameNode);
	}
      }
    }
    return agentLookUpReplyNode;
  }
  
  public String toString(){
    StringBuffer buff=new StringBuffer("MRAgentLookUpReply data is :");
    if(!AgentList.isEmpty()) {
      int counter=0;
      ListIterator iter=AgentList.listIterator();
      MessageAddress agentid=null;
      while(iter.hasNext()) {
	agentid=(MessageAddress)iter.next();
	buff.append(" Agent no :"+ counter+" agent Name :"+ agentid.toString()+"\n");
	counter++;
      }
    }
    return buff.toString();
  }
  
}
