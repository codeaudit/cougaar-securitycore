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
 
 
 
 
 
 
 
 


package org.cougaar.core.security.access;

import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceListener;
import org.cougaar.core.security.acl.trust.IntegrityAttribute;
import org.cougaar.core.security.acl.trust.MissionCriticality;
import org.cougaar.core.security.acl.trust.TrustAttribute;
import org.cougaar.core.security.acl.trust.TrustSet;
import org.cougaar.core.security.policy.AccessControlPolicy;
import org.cougaar.core.security.policy.GuardRegistration;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.services.acl.AccessControlPolicyService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import java.util.Vector;

import safe.enforcer.AgentEnforcer;

public class AccessControlPolicyServiceImpl
  implements AccessControlPolicyService
{
  private SecurityPropertiesService secprop = null;
  private Logger log;
  private CommunityService _commu;
  private ServiceBroker serviceBroker;
  private ServiceListener _communitySL;

  //policy for society--usually the default, one-fits-all policy
  AccessControlPolicy acp_in = null;
  AccessControlPolicy acp_out = null;
  
  //policy for community--common policy for the team
  AccessControlPolicy commu_in = null;
  AccessControlPolicy commu_out = null;

  //policy for agent--the one and only
  AccessControlPolicy agent_in = null;
  AccessControlPolicy agent_out = null;

  /** 
   * Creates new AccessControlPolicyServiceImpl 
   */
  public AccessControlPolicyServiceImpl(ServiceBroker sb, String name) {
    serviceBroker = sb;
    // Get Security Properties service
    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
		    SecurityPropertiesService.class,
		    null);

    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    if(log == null) {
      log = LoggerFactory.getInstance().createLogger(this);
    } 
    _commu = (CommunityService)
      serviceBroker.getService(this, CommunityService.class, null);
    if(_commu == null) {
      if(log.isDebugEnabled()){
        log.debug("Can't get community Service. Registering as service listener");
      } 
      ServiceAvailableListener sal = new ServiceAvailableListener() {  
          public void serviceAvailable(ServiceAvailableEvent ae) {
            if(ae.getService() == CommunityService.class) {
              log.debug("community service is now available");
              _commu = (CommunityService)
                ae.getServiceBroker().getService(this, CommunityService.class, null);
                removeServiceListener();
            }
          }
        };
      serviceBroker.addServiceListener(sal);
      _communitySL = sal;
    }
    //create a new policy proxy, pass the agent name the proxy is for.
    new AccessPolicyProxy(name, serviceBroker);
  }//Constructor

  private void removeServiceListener() {
    if(_communitySL != null) {
      serviceBroker.removeServiceListener(_communitySL);
    }
  }

  private AccessControlPolicy getIncomingPolicy(String target){
    if( agent_in != null ) {
      return agent_in;
    }else if( commu_in != null ){
      return commu_in;
    }else if( acp_in != null){
      return acp_in;
    }else{
      if(log.isDebugEnabled()) {
        log.debug("Can't find policy for " 
        + "->" +  target);
      }
      return null;
    }
  }//getIncomingPolicy

  private AccessControlPolicy getOutgoingPolicy(String source){
    if( agent_in != null ) {
      return agent_in;
    }else if( commu_in != null ){
      return commu_in;
    }else if( acp_in != null){
      return acp_in;
    }else{
      if(log.isDebugEnabled()) {
        log.debug("Can't find policy for " 
        + source + "->");
      }
      return null;
    }
  }//getOutgoingPolicy

  public TrustSet getIncomingTrust(String source, String target)
  {
    AccessControlPolicy acp = getIncomingPolicy(target);
    if(acp==null){
      //no point to go on.
      return null;
    }

    Object obj = acp.getCriticality(source);
    if (obj==null) return null;
    
    if(log.isDebugEnabled()) {
      log.debug("Msg IN:" + source + "->" + target
       + ". Criticality:" + obj);
    }
    TrustSet ts = new TrustSet();
    ts.addAttribute(new TrustAttribute(MissionCriticality.name, obj));

    obj = acp.getIntegrity(source);
    if (obj==null) return null;

    if(log.isDebugEnabled()) {
      log.debug("Msg IN:" + source + "->" + target
			 +". Integrity:"+obj);
    }
    ts.addAttribute(new TrustAttribute(IntegrityAttribute.name, obj));

    return ts;
  }//getIncomingTrust

  public TrustSet getOutgoingTrust(String source, String target) {
    AccessControlPolicy acp = getOutgoingPolicy(source);
    if(acp==null){
      //no point to go on.
      return null;
    }
    
    Object obj = acp.getCriticality(target);
    if (obj==null) return null;
    
    if(log.isDebugEnabled()) {
      log.debug("Msg OUT:" + source + "->" + target
       + ". Criticality:" + obj);
    }

    TrustSet ts = new TrustSet();
    ts.addAttribute(new TrustAttribute(MissionCriticality.name, obj));

    obj = acp.getIntegrity(target);
    if (obj==null) return null;

    if(log.isDebugEnabled()) {
      log.debug("Msg OUT:" + source + "->" + target
			 +". Integrity:"+obj);
    }
    ts.addAttribute(new TrustAttribute(IntegrityAttribute.name, obj));

    return ts;
  }//getOutgoingTrust

  public String getIncomingAction(String target, String level){
    AccessControlPolicy acp = getIncomingPolicy(target);
    if(acp==null){
      //no point to go on.
      return null;
    }

    String r = (String)acp.getMsgAction(level);
    if(log.isDebugEnabled()) {
      String s = "Msg In:" + "->" + target + ". Action:" +
    	(r == null ? "No policy" : r) + " for level " + level;
      log.debug(s);
    }
    return r;
  }//getIncomingAction

  public String getOutgoingAction(String source, String level){
    AccessControlPolicy acp = getOutgoingPolicy(source);
    if(acp==null){
      //no point to go on.
      return null;
    }
    
    String r = (String)acp.getMsgAction(level);
    if(log.isDebugEnabled()) {
      String s = "Msg OUT:" + source + "->" + ". Action:" +
    	(r == null ? "No policy" : r) + " for level " + level;
      log.debug(s);
    }
    return r;
  }//getOutgoingAction

  public String getIncomingAgentAction(String source,
						    String target) {
    AccessControlPolicy acp = getIncomingPolicy(target);
    if(acp==null){
      //no point to go on.
      return null;
    }

    String r = (String)acp.getAgentAction(source);
    if(log.isDebugEnabled()) {
      log.debug("Msg IN:" + source + "->" + target +
			 ". Agent action:" + r);
    }
    return r;
  }//getIncomingAgentAction

  public String getOutgoingAgentAction(String source,
						    String target) {
    AccessControlPolicy acp = getOutgoingPolicy(source);
    if(acp==null){
      //no point to go on.
      return null;
    }
    
    String r = (String)acp.getAgentAction(target);
    if(log.isDebugEnabled()) {
      log.debug("Msg OUT: " + source + "->" + target
			 +". Outgoing agent action:" + r);
    }
    return r;
  }//getOutgoingAgentAction

  public String[] getIncomingVerbs(String source, String target)
  {
    AccessControlPolicy acp = getIncomingPolicy(target);
    if(acp==null){
      //no point to go on.
      return null;
    }
    
    Vector r = (Vector)acp.getVerbs(source);
    if(log.isDebugEnabled()) {
      log.debug("Msg IN:" + source + "->" + target
         + ". Verbs:");
      for(int i = 0; i < r.size(); i++)
        log.debug(r.get(i).toString() + " ");
    }
    String[] verbs = new String[r.size()];
    try {
      for(int i = 0; i < r.size(); i++){
        verbs[i] = r.get(i).toString();
      }
    }
    catch(Exception ex) {
      log.debug("Warning: bad verb array:" + ex);
    }
    return verbs;
  }

  public String[] getOutgoingVerbs(String source, String target) {
    AccessControlPolicy acp = getOutgoingPolicy(source);
    if(acp==null){
      //no point to go on.
      return null;
    }

    Vector r = (Vector)acp.getVerbs(target);
    if(log.isDebugEnabled()) {
      log.debug("Msg OUT:" + source + "->" + target
		       +". Verbs:");
      for(int i = 0; i < r.size(); i++)
      log.debug(r.get(i).toString() + ":"
			 + r.get(i).getClass().getName() + " ");
    }
    String[] verbs = new String[r.size()];
    try {
      for(int i = 0; i < r.size(); i++){
        verbs[i] = r.get(i).toString();
      }
    }
    catch(Exception ex) {
      log.warn("Warning: bad verb array:" + ex);
    }
    return verbs;
  }

  /** ********************************************************************
   *  AccessPolicyProxy
   */
  private class AccessPolicyProxy
    extends GuardRegistration
    implements AgentEnforcer
  {
    private String agent;
    //private boolean debug=this.debug;
    public AccessPolicyProxy(String name, ServiceBroker sb) {
      super("org.cougaar.core.security.policy.AccessControlPolicy", name, sb);
      agent = name;
      if(log.isDebugEnabled())
	log.debug("--adding AccessPolicyProxy for:"+ agent);
      try {
      	registerEnforcer();
      }
      catch(Exception ex) {
        ex.printStackTrace();
      }
    }

    public void receivePolicyMessage(Policy policy,
				     String policyID,
				     String policyName,
				     String policyDescription,
				     String policyScope,
				     String policySubjectID,
				     String policySubjectName,
				     String policyTargetID,
				     String policyTargetName,
				     String policyType) {
      if(log.isDebugEnabled())
	log.debug("Got outdated policy format at AccessPolicyProxy for:"
		  + agent);
    }

    private class PolicyMessage {
      SecurityPolicy policy;
      String policyID;
      String policyName;
      String policyDescription;
      String policyScope;
      String policySubjectID;
      String policySubjectName;
      String policyTargetID;
      String policyTargetName;
      String policyType;
    }

    public void receivePolicyMessage(SecurityPolicy policy,
				     String policyID,
				     String policyName,
				     String policyDescription,
				     String policyScope,
				     String policySubjectID,
				     String policySubjectName,
				     String policyTargetID,
				     String policyTargetName,
				     String policyType) {
      if(log.isDebugEnabled())
	log.debug("--updating AccessPolicyProxy for:"
		  + agent);
      
      if(!(policy instanceof AccessControlPolicy)) {
        if (log.isDebugEnabled()) {
          log.debug("receivePolicyMessage: wrong policy type: " + policy);
        }
        return;
      }
      
      AccessControlPolicy acp = (AccessControlPolicy)policy;
      
      switch(acp.Type){
      case  AccessControlPolicy.AGENT:
        if(!agent.equalsIgnoreCase(acp.Name)){
          if (log.isWarnEnabled()) {
            log.warn("Agent " + agent + " received policy intended for " 
              + acp.Name + "; policy not accepted." );
          }
          return;
        }
        if(acp.Direction == AccessControlPolicy.INCOMING){
          agent_in = acp;
        }else if(acp.Direction == AccessControlPolicy.OUTGOING){
          agent_out = acp;
        }else if(acp.Direction == AccessControlPolicy.BOTH){
          agent_in = acp;
          agent_out = acp;
        }
        break;
      case  AccessControlPolicy.COMMUNITY:
        if (_commu == null) return;
	log.warn("Communities no longer supported");
	/*
	CommunityResponseListener crl = new CommunityResponseListener();
	_commu.searchCommunity(acp.Name, filter, false,
			       CommunityService.AGENT, crl);
        Collection c = _commu.listEntities(acp.Name);
        if(c.contains(agent)){
          if(acp.Direction == AccessControlPolicy.INCOMING){
            commu_in = acp;
          }else if(acp.Direction == AccessControlPolicy.OUTGOING){
            commu_out = acp;
          }else if(acp.Direction == AccessControlPolicy.BOTH){
            commu_in = acp;
            commu_out = acp;
          }
        }else{
          if(log.isWarnEnabled()){
            log.warn("The community--" + acp.Name + 
              "specified in the policy does not contain the agent:" + agent);
          }
          return;
        }
	*/
        
        //expand community to a list of agents
	/*
	CommunityRoster cr = commu.getRoster(acp.Name);
        if(cr == null ){
          //community doesn't exist.
          if(log.isWarnEnabled()){
          log.warn("The community--" + acp.Name + 
            " specified in the policy can't be found.");
          }
          return;
        }
        Collection c = cr.getMemberAgents();
        boolean match = false;
        while(c.iterator().hasNext()){
          String agt = c.iterator().next().toString();
          if(agt.equalsIgnoreCase(agent)){
            match = true;
            break;
          }
        }
        //only accept the policy for the community the agent is in.
        if(match){
            if(acp.Direction == AccessControlPolicy.INCOMING){
              commu_in = acp;
            }else if(acp.Direction == AccessControlPolicy.OUTGOING){
              commu_out = acp;
            }else if(acp.Direction == AccessControlPolicy.BOTH){
              commu_in = acp;
              commu_out = acp;
            }
        }else{
          if(log.isWarnEnabled()){
            log.warn("The community--" + acp.Name + 
              "specified in the policy does not contain the agent:" + agent);
          }
          return;
      }
	*/
        break;
      case  AccessControlPolicy.SOCIETY:
        if(acp.Direction == AccessControlPolicy.INCOMING){
          acp_in = acp;
        }else if(acp.Direction == AccessControlPolicy.OUTGOING){
          acp_out = acp;
        }else if(acp.Direction == AccessControlPolicy.BOTH){
          acp_in = acp;
          acp_out = acp;
        }
      }//switch
      //update community list
      if(_commu!=null) acp.setCommunityService(_commu);
      return;
    }
    
    public String getAgentName() {
      return agent;
    }

    public String getAgentId() {
      return agent;
    }
  }
}
