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

import java.util.*;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceAvailableEvent;

// KAoS policy management
import safe.enforcer.NodeEnforcer;

// Cougaar security services
import org.cougaar.core.security.policy.*;
import org.cougaar.planning.ldm.policy.*;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
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
  DataProtectionPolicyProxy dpp;

  //policy for society--usually the default, one-fits-all policy
  CryptoPolicy dcp_in = null;
  CryptoPolicy dcp_out = null;
  CryptoPolicy dcp_dataprot = null;


  //policy for community--common policy for the team
  HashMap incoming_c = new HashMap();
  HashMap outgoing_c = new HashMap();
  HashMap dataprot_c = new HashMap();

  //policy for agent--the one and only
  HashMap incoming_a = new HashMap();
  HashMap outgoing_a = new HashMap();
  HashMap dataprot_a = new HashMap();

  /** Creates new CryptoPolicyServiceImpl */
  public CryptoPolicyServiceImpl(ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class, null);
/*
    commu = (CommunityService)
      serviceBroker.getService(this, CommunityService.class, null);


    if(commu==null && log.isWarnEnabled()){
      log.warn("can't get community Service.");
    }
*/
    // check to see if CommunityService is available
    // if not, add listener
    if(serviceBroker.hasService
      (org.cougaar.core.service.community.CommunityService.class)){
        commu = (CommunityService)
          sb.getService(this, CommunityService.class, null);
        log.info("CommunityService is available initially");
    }
    else {
      serviceBroker.addServiceListener(new CommunityServiceAvailableListener());
    }

    cpp = new CryptoPolicyProxy(serviceBroker);
    dpp = new DataProtectionPolicyProxy(serviceBroker);
  }

  private class CommunityServiceAvailableListener implements ServiceAvailableListener
  {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      if (org.cougaar.core.service.community.CommunityService.
        class.isAssignableFrom(sc)) {
                commu = (CommunityService)
                serviceBroker.getService(this, CommunityService.class, null);
                log.info("BlackboardService is available now");
            }
    }
  }

    public SecureMethodParam getSendPolicy(String source, String target) {
      if(log.isDebugEnabled()) {
        log.debug("Outgoing SecureMethodParam for "
               + source );
      }

      CryptoPolicy p = getOutgoingPolicy(source);
      if (p==null) return null;

      SecureMethodParam smp = new SecureMethodParam();
      smp = p.getSecureMethodParam(target);

      if(smp==null){
          log.error("Failed converting CryptoPolicy " + p);
      }
      return smp;
    }

    public CryptoPolicy getOutgoingPolicy(String source) {
      if(log.isDebugEnabled()) {
        log.debug("getting outgoing CryptoPolicy for " + source);
      }

      //try agent first
      CryptoPolicy cp = (CryptoPolicy)outgoing_a.get(source);

      if(cp==null && outgoing_c.size()>0){
        cp = (CryptoPolicy)outgoing_c.get(source);
      }

      if(cp==null){
        //last try
        cp = dcp_out;
      }

      if(cp==null){
          log.error("Can't find policy for " + "->" +  source);
      }

      return cp;
    }

    public SecureMethodParam getReceivePolicy(String source, String target) {
      if(log.isDebugEnabled()) {
        log.debug("Incoming SecureMethodParam for "
               + target );
      }

      CryptoPolicy p = getIncomingPolicy(target);
      if (p==null) return null;

      SecureMethodParam smp = new SecureMethodParam();
      smp = p.getSecureMethodParam(source);

      if(smp==null){
          log.error("Failed converting CryptoPolicy " + p);
      }
      return smp;
    }

  public Collection getSendPolicies(String source, String target) {
    return Collections.singletonList(getSendPolicy(source, target));
  }

  public Collection getReceivePolicies(String source, String target) {
    return Collections.singletonList(getReceivePolicy(source, target));
  }

    public CryptoPolicy getIncomingPolicy(String target) {
      if(log.isDebugEnabled()) {
        log.debug("getting incoming CryptoPolicy for " + target);
      }

      //try agent first
      CryptoPolicy cp = (CryptoPolicy)incoming_a.get(target);

      if(cp==null && incoming_c.size()>0){
        cp = (CryptoPolicy)incoming_c.get(target);
      }

      if(cp==null){
        //last try
        cp = dcp_in;
      }

      if(cp==null){
          log.debug("can't find policy for " + "->" +  target);
      }
      return cp;
    }

    public CryptoPolicy getDataProtectionPolicy(String source) {
      if(log.isDebugEnabled()) {
        log.debug("getting DataProtection CryptoPolicy for " + source);
      }

      //try agent first
      CryptoPolicy cp = (CryptoPolicy)dataprot_a.get(source);

      if(cp==null && dataprot_c.size()>0){
        cp = (CryptoPolicy)dataprot_c.get(source);
      }

      if(cp==null){
        //last try
        cp = dcp_dataprot;
      }

      if(cp==null){
          log.debug("can't find policy for " + "->" +  source);
          return null;
      }

      return cp;
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
          incoming_a.put(cp.Name, cp);
        }else if(cp.Direction == CryptoPolicy.OUTGOING){
          outgoing_a.put(cp.Name, cp);
        }else if(cp.Direction == CryptoPolicy.BOTH){
          incoming_a.put(cp.Name, cp);
          outgoing_a.put(cp.Name, cp);
        }
        break;
      case  CryptoPolicy.COMMUNITY:
        if (commu == null) return;
        Collection c = commu.listEntities(cp.Name);
        Iterator iter = c.iterator();
        while(iter.hasNext()){
          String name = (String)iter.next();
          if(cp.Direction == CryptoPolicy.INCOMING){
            incoming_c.put(name, cp);
          }else if(cp.Direction == CryptoPolicy.OUTGOING){
            outgoing_c.put(name, cp);
          }else if(cp.Direction == CryptoPolicy.BOTH){
            incoming_c.put(name, cp);
            outgoing_c.put(name, cp);
          }
        }
        break;
      case  CryptoPolicy.SOCIETY:
        log.debug("CryptoPolicy for SOCIETY: " + cp.Direction);
        if(cp.Direction == CryptoPolicy.INCOMING){
          dcp_in = cp;
        }else if(cp.Direction == CryptoPolicy.OUTGOING){
          dcp_out = cp;
        }else if(cp.Direction == CryptoPolicy.BOTH){
          dcp_in = cp;
          dcp_out = cp;
        }
      }//switch
      //update community list in cp.
      if(commu!=null) {
        cp.setCommunityService(commu);
      }

      return;
    }
  }

    private class DataProtectionPolicyProxy
      extends GuardRegistration
      implements NodeEnforcer{

      public DataProtectionPolicyProxy(ServiceBroker sb) {

        super("org.cougaar.core.security.policy.DataProtectionPolicy",
              "CryptoPolicyService", sb);
        if (log.isDebugEnabled()) {
          log.debug("Registering data protection policy service to guard");
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
        log.debug("CryptoPolicy: " + policy);
        }

      if(!(policy instanceof DataProtectionPolicy)) {
        if (log.isErrorEnabled()) {
          log.error("wrong policy type.");
        }
        return;
      }

      CryptoPolicy cp = null;
      try{
        cp = ((DataProtectionPolicy)policy).getCryptoPolicy();
      }catch(Exception e){
        log.debug("received unknown policy type.");
        return;
      }

      switch(cp.Type){
      case  CryptoPolicy.AGENT:
        if(cp.Direction == CryptoPolicy.DATAPROTECTION){
          dataprot_a.put(cp.Name, cp);
        }
        break;
      case  CryptoPolicy.COMMUNITY:
        if (commu == null) return;
        Collection c = commu.listEntities(cp.Name);
        Iterator iter = c.iterator();
        while(iter.hasNext()){
          String name = (String)iter.next();
          if(cp.Direction == CryptoPolicy.DATAPROTECTION){
            dataprot_c.put(name, cp);
          }
        }
        break;
      case  CryptoPolicy.SOCIETY:
        log.debug("CryptoPolicy for SOCIETY: " + cp.Direction);
        if(cp.Direction == CryptoPolicy.DATAPROTECTION){
          dcp_dataprot = cp;
        }
      }
      return;
    }
  }

}
