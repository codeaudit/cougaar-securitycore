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


package org.cougaar.core.security.test.blackboard;


import java.net.InetAddress;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.security.monitoring.event.BlackboardFailureEvent;
import org.cougaar.core.security.monitoring.plugin.BlackboardCompromiseSensorPlugin;
import org.cougaar.core.security.monitoring.plugin.CompromiseBlackboard;
import org.cougaar.core.security.test.AbstractServletComponent;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.security.util.NodeInfo;


/**
 * Just simulates an sensor detecting a blackboard compromise and then
 * publishing a compromise object to the Blackboard. The only url parameter
 * is <i>scope<i> which is the scope of the compromise, either Agent, Node or Host
 */
public class CompromiseBlackboardServlet extends AbstractServletComponent {
  private static final String pluginName = "CompromiseBlackboardServlet";
  private static final String SCOPE_PARAM="scope";
  /**
   * Path to servlet
   *
   * @return path to Servlet
   */
  protected String getPath() {
  	
    return "/compromiseBlackboard";
    
  }
	
	

  /**
   * Just publish a compromise object to the blackboard
   *
   * @param request ServletRequest
   * @param response ServletResponse
   */
  protected void execute(HttpServletRequest request, HttpServletResponse response) {
    UIDService uidService = (UIDService) this.serviceBroker.getService(this, UIDService.class, null);
    try{
  	AgentIdentificationService agentIdService = (AgentIdentificationService)this.serviceBroker.getService(this,AgentIdentificationService.class, null);
        String agent = agentIdService.getMessageAddress().getAddress();
	
    	//create BlackboardCompromise Object
    	String scope = request.getParameter(SCOPE_PARAM);
    	if(scope==null || scope.trim().length()==0){
    		if(logging.isWarnEnabled()){
    			logging.warn("No compromise scope in url query string, using agent scope!");
    		}
    		scope = CompromiseBlackboard.AGENT_COMPROMISE_TYPE;
        }

	String data="";
	data=data + "scope=" + scope;
        data=data+",compromise timestamp=" + System.currentTimeMillis();
  	data=data+",sourceAgent=" + agent;
	String nodeName = NodeInfo.getNodeName();
  	data=data+",sourceNode="+nodeName;
  	String hostName = NodeInfo.getHostName();
  	data=data+",sourceHost=" + hostName;
	
	BlackboardFailureEvent event = 
          new BlackboardFailureEvent(agent,agent,"reason",
		"reasonId", data, "compromisedata");
     	BlackboardCompromiseSensorPlugin.publishEvent(event);
    
   
      String msg = "Published CompromiseBlackboard Object for " + agent;
    PrintWriter out = response.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println(msg);
    out.println("</html>");
    out.flush();
    out.close();
    }catch(Exception e){
    	logging.error("Error reporting blackboardCompromise " + e.toString());
    }
  }
}
  

