/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


package org.cougaar.core.security.cm;


import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;


/**
 * Society Configuration Value Object
 *
 * @author ttschampel
 * @version $Revision: 1.2 $
 */
public class SocietyConfiguration implements Serializable, UniqueObject {
  private HashMap agentConfigurations;
  private HashMap nodeConfigurations;
  private UID uid;

	/**
	 * @return
	 */
	public HashMap getNodeConfigurations() {
		return nodeConfigurations;
	}

	/**
	 * @param nodeConfigurations
	 */
	public void setNodeConfigurations(HashMap nodeConfigurations) {
		this.nodeConfigurations = nodeConfigurations;
	}

	/**
	 * @return
	 */
	public HashMap getAgentConfigurations() {
		return agentConfigurations;
	}

  /**
   * Creates a new SocietyConfiguration object.
   *
   * @param list List of agent to node mappings.
   */
  public SocietyConfiguration(HashMap agentList, HashMap nodeList) {
    this.agentConfigurations = agentList;
    this.nodeConfigurations = nodeList;
    
  }

  /**
   *Gets UID
   */
  public UID getUID() {
    return uid;
  }


  /**
   *Sets UID
   */
  public void setUID(UID arg0) {
    uid = arg0;
  }
  
  public String toString(){
  	String result="";
	result = result + "\nNode configs:\n";
  	if(nodeConfigurations!=null)
  	{
  		
  		Set entries = nodeConfigurations.keySet();
  		Iterator iter = entries.iterator();
  		while(iter.hasNext()){
  			String key = (String)iter.next();
  			NodeConfiguration nc = (NodeConfiguration)nodeConfigurations.get(key);
  			result = result + nc.getNodeName() +":"+nc.getNodeType()+"\n";
  		}
  	}
	result= result + "\nAgent configs:\n";
  	if(agentConfigurations!=null){
  		Set entries = agentConfigurations.keySet();
  		Iterator iter = entries.iterator();
  		while(iter.hasNext()){
  			String key = (String)iter.next();
  			AgentConfiguration ac = (AgentConfiguration)agentConfigurations.get(key);
  			result = result + ac.getAgentname()+":"+ac.getAgentType()+"\n";
  		}
  	}
  	return result;
  }
}
