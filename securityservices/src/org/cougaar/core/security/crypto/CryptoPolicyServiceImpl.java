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
 *
 * Created on September 21, 2001, 4:17 PM
 */

package org.cougaar.core.security.crypto;

import java.util.HashMap;
import java.util.Set;
import java.util.Iterator;
import java.util.Vector;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.component.ServiceBroker;

// KAoS policy management
import safe.enforcer.NodeEnforcer;

// Cougaar security services
import org.cougaar.core.security.policy.*;
import org.cougaar.planning.ldm.policy.*;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.security.crypto.SecureMethodParam;

public class CryptoPolicyServiceImpl
  implements CryptoPolicyService
{
  private SecurityPropertiesService secprop = null;
  private ServiceBroker serviceBroker;
  private LoggingService log;
  private CommunityService commu;

  //policy source
  CryptoPolicyProxy cpp;

  //policy for society--usually the default, one-fits-all policy
  CryptoPolicy dcp_in = null;
  CryptoPolicy dcp_out = null;
  
  //policy for community--common policy for the team
  CryptoPolicy incoming_c = null;
  CryptoPolicy outgoing_c = null;

  //policy for agent
  CryptoPolicy incoming_a = null;
  CryptoPolicy outgoing_a = null;

  /** Creates new CryptoPolicyServiceImpl */
  public CryptoPolicyServiceImpl(ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class, null);

    commu = (CommunityService)
      serviceBroker.getService(this, CommunityService.class, null);

    cpp = new CryptoPolicyProxy(serviceBroker);
  }

    public SecureMethodParam getSendPolicy(String name) {
      if(log.isDebugEnabled()) {
        log.debug("Outgoing SecureMethodParam for "
               + name );
      }

      //agent first
      if(outgoing_a != null){
        return outgoing_a.getSecureMethodParam(name);
      }
      
      //then community
      if(outgoing_c != null){
        return outgoing_c.getSecureMethodParam(name);
      }

      //default last
      if(dcp_out != null){
        return dcp_out.getSecureMethodParam(name);
      }
      
      //fall through, this probably results a "throw" somewhere.
      return null;
    }

    public CryptoPolicy getOutgoingPolicy() {
      if(log.isDebugEnabled()) {
        log.debug("getting outgoing CryptoPolicy.");
      }

      //agent first
      if(outgoing_a != null){
        return outgoing_a;
      }
      
      //then community
      if(outgoing_c != null){
        return outgoing_c;
      }

      //default last
      if(dcp_out != null){
        return dcp_out;
      }
      
      //fall through, this probably results a "throw" somewhere.
      return null;
    }
    
    public SecureMethodParam getReceivePolicy(String name) {
      if(log.isDebugEnabled()) {
        log.debug("Incoming SecureMethodParam for "
               + name );
      }

      //agent first
      if(incoming_a != null){
        return incoming_a.getSecureMethodParam(name);
      }
      
      //then community
      if(incoming_c != null){
        return incoming_c.getSecureMethodParam(name);
      }

      //default last
      if(dcp_in != null){
        return dcp_in.getSecureMethodParam(name);
      }
      
      //fall through, this probably results a "throw" somewhere.
      return null;
    }

    public CryptoPolicy getIncomingPolicy() {
      if(log.isDebugEnabled()) {
        log.debug("getting incoming CryptoPolicy.");
      }

      //agent first
      if(incoming_a != null){
        return incoming_a;
      }
      
      //then community
      if(incoming_c != null){
        return incoming_c;
      }

      //default last
      if(dcp_in != null){
        return dcp_in;
      }
      
      //fall through, this probably results a "throw" somewhere.
      return null;
    }

    private class CryptoPolicyProxy
      extends GuardRegistration
      implements NodeEnforcer{

      public CryptoPolicyProxy(ServiceBroker sb) {
        
        super("org.cougaar.core.security.policy.CryptoPolicy",
              "CryptoPolicyService", sb);
        if (log.isDebugEnabled()) {
          log.debug("Registering crypto policy service to guard");
        }
        try {
          registerEnforcer();
        }
        catch(Exception ex) {
          ex.printStackTrace();
        }
      }

      /**
       * Merges an existing policy with a new policy.
       * @param policy the new policy to be added
       */
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
            + policySubjectID);
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
      
      if (log.isDebugEnabled()) {
          log.debug("Received policy message for: " + policySubjectID);
        }

      if(!(policy instanceof CryptoPolicy)) {
        if (log.isErrorEnabled()) {
          log.error("wrong policy type.");
        }
        return;
      }
      
      CryptoPolicy cp = null;
      try{
        cp = (CryptoPolicy)policy;
      }catch(Exception e){
        log.debug("received unknown policy type.");
        return;
      }
      
      switch(cp.Type){
      case  CryptoPolicy.AGENT:
        if(cp.Direction == CryptoPolicy.INCOMING){
          incoming_a = cp;
        }else if(cp.Direction == CryptoPolicy.OUTGOING){
          outgoing_a = cp;
        }else if(cp.Direction == CryptoPolicy.BOTH){
          incoming_a = cp;
          outgoing_a = cp;
        }
        break;
      case  CryptoPolicy.COMMUNITY:
        if(cp.Direction == CryptoPolicy.INCOMING){
          incoming_c = cp;
        }else if(cp.Direction == CryptoPolicy.OUTGOING){
          outgoing_c = cp;
        }else if(cp.Direction == CryptoPolicy.BOTH){
          incoming_c = cp;
          outgoing_c = cp;
        }
        break;
      case  CryptoPolicy.SOCIETY:
        if(cp.Direction == CryptoPolicy.INCOMING){
          dcp_in = cp;
        }else if(cp.Direction == CryptoPolicy.OUTGOING){
          dcp_out = cp;
        }else if(cp.Direction == CryptoPolicy.BOTH){
          dcp_in = cp;
          dcp_out = cp;
        }
      }
      return;
    }     
  }
}
