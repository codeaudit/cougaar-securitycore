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
import java.util.ListIterator;
import java.io.Serializable;

import org.cougaar.core.agent.ClusterIdentifier;


public class MRAgentLookUpReply implements java.io.Serializable {

  private  List AgentList;

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
  
  public String toString(){
    StringBuffer buff=new StringBuffer("MRAgentLookUpReply data is :");
    if(!AgentList.isEmpty()) {
      int counter=0;
      ListIterator iter=AgentList.listIterator();
      ClusterIdentifier agentid=null;
      while(iter.hasNext()) {
	agentid=(ClusterIdentifier)iter.next();
	buff.append(" Agent no :"+ counter+" agent Name :"+ agentid.toString()+"\n");
	counter++;
      }
    }
    return buff.toString();
  }
  

}
