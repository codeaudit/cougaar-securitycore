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


package org.cougaar.core.security.crypto;

import java.util.HashMap;

import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.CryptoPolicy;
import org.cougaar.core.security.policy.DataProtectionPolicy;
import org.cougaar.core.security.policy.GuardRegistration;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.planning.ldm.policy.Policy;

import safe.enforcer.NodeEnforcer;

public class CryptoPolicyServiceImpl
  implements CryptoPolicyService
{
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
                if (log.isInfoEnabled()) {
                  log.info("CommunityService is available now");
                }
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

  public int isReceivePolicyValid(String source, String target,
                                  SecureMethodParam policy,
                                  boolean ignoreEncryption,
                                  boolean ignoreSignature)
  {
    if(log.isDebugEnabled()) {
      log.debug("isReceivePolicyValid for " + source + " to " + target +
                ", policy = " + policy + ", ignore encryption = " +
		ignoreEncryption + ", ignoreSignature = " + ignoreSignature);
    }
    SecureMethodParam realPolicy = getReceivePolicy(source, target);

    if (!ignoreEncryption) {
      boolean realEncrypt = 
        realPolicy.secureMethod == SecureMethodParam.SIGNENCRYPT ||
        realPolicy.secureMethod == SecureMethodParam.ENCRYPT;

      boolean encrypt = 
        policy.secureMethod == SecureMethodParam.SIGNENCRYPT ||
        policy.secureMethod == SecureMethodParam.ENCRYPT;

      if (realEncrypt) {
        if (!encrypt || policy.symmSpec == null || 
            !policy.symmSpec.equals(realPolicy.symmSpec) ||
            policy.asymmSpec == null ||
            !policy.asymmSpec.equals(realPolicy.asymmSpec)) {
          return CRYPTO_SHOULD_ENCRYPT;
        }
      }
    }

    if (!ignoreSignature) {
      boolean realSign = 
        realPolicy.secureMethod == SecureMethodParam.SIGNENCRYPT ||
        realPolicy.secureMethod == SecureMethodParam.SIGN;

      boolean sign = 
        policy.secureMethod == SecureMethodParam.SIGNENCRYPT ||
        policy.secureMethod == SecureMethodParam.SIGN;

      if (realSign) {
        if (!sign || policy.signSpec == null || 
            !policy.signSpec.equals(realPolicy.signSpec)) {
          return CRYPTO_SHOULD_SIGN;
        }
      }
    }

    return CRYPTO_POLICY_VALID;
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
          if (log.isDebugEnabled()) {
            log.debug("can't find policy for " + "->" +  source);
          }
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
	  if (log.isWarnEnabled()) {
	    log.warn("Unable to register Crypto Policy enforcer - Will continue without policy");
	  }
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
	log.warn("Communities no longer supported");
	/*
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
	*/
        break;
      case  CryptoPolicy.SOCIETY:
        if (log.isDebugEnabled()) {
          log.debug("CryptoPolicy for SOCIETY: " + cp.Direction);
        }
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

      private CryptoPolicyServiceImpl _legacy;

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
          // Implement a default policy
          dcp_dataprot = getDataProtectionPolicy("");
	  if (log.isWarnEnabled()) {
	    log.warn("Unable to register enforcer - DataProtection will continue without policy");
	  }
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
	log.warn("Communities no longer supported");
	/*
        Collection c = commu.listEntities(cp.Name);
        Iterator iter = c.iterator();
        while(iter.hasNext()){
          String name = (String)iter.next();
          if(cp.Direction == CryptoPolicy.DATAPROTECTION){
            dataprot_c.put(name, cp);
          }
        }
	*/
        break;
      case  CryptoPolicy.SOCIETY:
        if (log.isDebugEnabled()) {
          log.debug("CryptoPolicy for SOCIETY: " + cp.Direction);
        }
        if(cp.Direction == CryptoPolicy.DATAPROTECTION){
          dcp_dataprot = cp;
        }
      }
      return;
    }
  }

}
