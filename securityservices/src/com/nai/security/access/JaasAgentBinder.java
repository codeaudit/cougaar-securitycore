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
 * Created on March 18, 2002, 2:42 PM
 */

package com.nai.security.access;

import org.cougaar.core.component.BinderWrapper;
import org.cougaar.core.component.BinderFactory;
import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ComponentDescription;
import org.cougaar.core.agent.AgentManagerForBinder;
import org.cougaar.core.agent.Agent;
import org.cougaar.core.agent.AgentBinder;

import com.nai.security.bootstrap.JaasClient;

public class JaasAgentBinder extends BinderWrapper implements AgentManagerForBinder{

    /** Creates new JassAgentBinder */
    public JaasAgentBinder(BinderFactory bf, Object child) {
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
    
   
    public String toString() {
        return "JaasAgentBinder for "+getAgentManager();
    }
    public String getName() {return getAgentManager().getName(); }
/*    
    public void initialize() {
        System.out.println("#####test:"+getAgentBinder().toString());
        super.initialize();
    }
*/
    private String getAgentName(){
        String tmp = getAgentBinder().toString();
        return tmp.substring(9, tmp.indexOf('>'));
    }

    private void doLoad() { super.load();}

    private void doStart() { super.start();}

    public void load() {
        JaasClient jc = new JaasClient();
        jc.doAs(getAgentName(),
            new java.security.PrivilegedAction() {
                public Object run() {
                  System.out.println("Agent manager is loading: "
                                     + getAgentName()
                                     + " security context is:");
                  JaasClient.printPrincipals();
                  doLoad();
                  return null;
                }
              });
    }

   
    public void start() {
        JaasClient jc = new JaasClient();
        jc.doAs(getAgentName(),
            new java.security.PrivilegedAction() {
                public Object run() {
                  System.out.println("Agent manager is starting: "
                                     + getAgentName()
                                     + " security context is:");
                  JaasClient.printPrincipals();
                  doStart();
                  return null;
                }
              });
    }
   
    public void registerAgent(Agent agent) {
        //just passing through
        getAgentManager().registerAgent(agent);
    }
    
}
