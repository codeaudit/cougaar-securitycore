/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 * Created on May 08, 2002, 2:42 PM
 */

package org.cougaar.core.security.access;

import org.cougaar.core.component.*;
import org.cougaar.core.agent.Agent;
import org.cougaar.core.agent.AgentBinder;
import org.cougaar.core.agent.AgentManagerForBinder;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.core.security.services.acl.AccessControlPolicyService;


public class AccessAgentBinder extends ServiceFilterBinder {

  public  AccessAgentBinder (BinderFactory bf,Object child) {
    super(bf,child);
  }
  
  //child binder
  protected final AgentBinder getAgentBinder() { 
    return (AgentBinder)getChildBinder(); 
  }    
  //parent
  protected final AgentManagerForBinder getAgentManager() { 
    return (AgentManagerForBinder)getContainer(); 
  }
  
  protected ContainerAPI createContainerProxy() {
    return new AccessAgentBinderProxy();
  }

  protected ServiceBroker createFilteringServiceBroker(ServiceBroker sb) {
    return new AccessAgentServiceBroker(sb);
  }

  protected class AccessAgentBinderProxy extends ServiceFilterContainerProxy implements AgentManagerForBinder {
     public void registerAgent(Agent agent) {
        //just passing through
        getAgentManager().registerAgent(agent);
    }
     public String getName() {
       return getAgentManager().getName(); 
     }
    
  }
  
  protected class AccessAgentServiceBroker extends FilteringServiceBroker {

    public AccessAgentServiceBroker(ServiceBroker sb) {
      super(sb);
    }
    
    protected Object getServiceProxy(Object service,Class serviceclass,Object client)  {
      if(service instanceof MessageTransportService) {
	ServiceBroker serviceBroker = getServiceBroker();
	AccessControlPolicyService acps=null;
	if (serviceBroker != null)  {
	  try  {
	    acps = (AccessControlPolicyService)
	      serviceBroker.getService(this,
				      AccessControlPolicyService.class, null);
	    if (acps == null) {
	     throw new RuntimeException("Access Crl Aspect. No policy service");
	    }
	  }
	  catch(Exception e)  {
	   System.out.println("ACL: Unable to get access control policy service:"
			      + e);
	   e.printStackTrace();
	   throw new RuntimeException("Access Control Aspect:"
				      +e.toString());
	  }
       }else{
	 System.out.println("ACL: Unable to get service broker");
	 throw new RuntimeException("Access Control Aspect: no service broker");
       }
      
	//System.out.println(" getting service broker :");
	return new AccessAgentProxy((MessageTransportService)service,client,acps,
				    serviceBroker);
	  
      }
      return null;
    }
  }
  

}
