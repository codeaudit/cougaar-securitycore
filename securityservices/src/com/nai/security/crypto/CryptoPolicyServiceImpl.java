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

package com.nai.security.crypto;

import java.util.HashMap;

import com.nai.security.policy.*;
import org.cougaar.domain.planning.ldm.policy.*;

import SAFE.Enforcer.NodeEnforcer;

public class CryptoPolicyServiceImpl implements CryptoPolicyService {

  private boolean dbg = false;

    //policy source
    CryptoPolicyProxy cpp;
    
    //params look-up by name  
    static HashMap hm = new HashMap(); 

    /** Creates new CryptoPolicyServiceImpl */
    public CryptoPolicyServiceImpl() {
      dbg = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.policy.debug",
						"false"))).booleanValue();
        cpp = new CryptoPolicyProxy();
    }

    public synchronized SecureMethodParam getSendPolicy(String name) {
        Object obj = hm.get(name);
        //if not found, try sender with default target
        if(obj==null) obj = hm.get(name.substring(0, name.indexOf(':'))+":DEFAULT");
        //still not found, last try with default sender and default target
        //usually the case at bootstrap
        if(obj==null) obj = hm.get("DEFAULT:DEFAULT");
	if(dbg) {
	  System.out.println("CryptoPolicyService: policy: " + name + " - Policy: " + obj);
	}
        return (SecureMethodParam)obj;
    }
    
    public synchronized SecureMethodParam getReceivePolicy(String name) {
        Object obj = hm.get(name);
        //if not found, try sender with default target
        if(obj==null) obj = hm.get("DEFAULT" + name.substring(name.indexOf(':')));
        //still not found, last try with default sender and default target
        //usually the case at bootstrap
        if(obj==null) obj = hm.get("DEFAULT:DEFAULT");
            
        return (SecureMethodParam)obj;
    }
    
    private class CryptoPolicyProxy extends GuardRegistration implements NodeEnforcer{
        
        public CryptoPolicyProxy() {
            super("org.cougaar.core.security.policy.CryptoPolicy",
		  "CryptoPolicyService");
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
    if (dbg) {
      System.out.println("CryptoPolicyServiceImpl: " + policy);
      RuleParameter[] param = policy.getRuleParameters();
      for (int i = 0 ; i < param.length ; i++) {
	System.out.println("Rule: " + param[i].getName() + " - " + param[i].getValue());
      }
    }

	if(policy == null)return;
        //whom is the policy for?
        String sub = policySubjectName;
        if(policy.getName().equalsIgnoreCase("BootPolicy")) sub = "DEFAULT";
        if(sub=="" || sub == null) return ;
        
        //for each RuleParameter
	RuleParameter[] ruleParameters = policy.getRuleParameters();
        for (int j=0; j < ruleParameters.length; j++)
        {
            if(!(ruleParameters[j] instanceof KeyRuleParameter)) return;
            KeyRuleParameter krp = (KeyRuleParameter)ruleParameters[j];
            //process rules on all the parameters within secureMethodParam
            String name = krp.getName();
            String value = (String)krp.getValue();
            KeyRuleParameterEntry[] entry = krp.getKeys();
            if(name.endsWith("SecureMethod")){
                if(name.startsWith("Outgoing")) {
                    if(value!=null) updateSecureMethod(sub+":"+"DEFAULT",value);
                    for(int i = 0; i < entry.length; i++) {
                      updateSecureMethod(sub+":"+entry[i].getKey(), entry[i].getValue());
                    }
                }
                if(name.startsWith("Incoming")) {
                    if(value!=null) updateSecureMethod("DEFAULT"+":"+sub,value);
                    for(int i = 0; i < entry.length; i++) {
                      updateSecureMethod(entry[i].getKey()+":"+sub, entry[i].getValue());
                    }
                }
            }
            
            if(name.endsWith("SymmetricAlgorithm")){
                if(name.startsWith("Outgoing")) {
                    if(value!=null) updateSymmetricAlgorithm(sub+":"+"DEFAULT",value);
                    for(int i = 0; i < entry.length; i++) {
                      updateSymmetricAlgorithm(sub+":"+entry[i].getKey(), entry[i].getValue());
                    }
                }
                if(name.startsWith("Incoming")) {
                    if(value!=null) updateSymmetricAlgorithm("DEFAULT"+":"+sub,value);
                    for(int i = 0; i < entry.length; i++) {
                      updateSymmetricAlgorithm(entry[i].getKey()+":"+sub, entry[i].getValue());
                    }
                }
            }
            
            if(name.endsWith("AsymmetricAlgorithm")){
                if(name.startsWith("Outgoing")) {
                    if(value!=null) updateAsymmetricAlgorithm(sub+":"+"DEFAULT",value);
                    for(int i = 0; i < entry.length; i++) {
                      updateAsymmetricAlgorithm(sub+":"+entry[i].getKey(), entry[i].getValue());
                    }
                }
                if(name.startsWith("Incoming")) {
                    if(value!=null) updateAsymmetricAlgorithm("DEFAULT"+":"+sub,value);
                    for(int i = 0; i < entry.length; i++) {
                      updateAsymmetricAlgorithm(entry[i].getKey()+":"+sub, entry[i].getValue());
                    }
                }
            }
            
            if(name.endsWith("SigningAlgorithm")){
                if(name.startsWith("Outgoing")) {
                    if(value!=null) updateSigningAlgorithm(sub+":"+"DEFAULT",value);
                    for(int i = 0; i < entry.length; i++) {
                      updateSigningAlgorithm(sub+":"+entry[i].getKey(), entry[i].getValue());
                    }
                }
                if(name.startsWith("Incoming")) {
                    if(value!=null) updateSigningAlgorithm("DEFAULT"+":"+sub,value);
                    for(int i = 0; i < entry.length; i++) {
                      updateSigningAlgorithm(entry[i].getKey()+":"+sub, entry[i].getValue());
                    }
                }
            }
        }
            
	    
    }
    
    private synchronized void updateSecureMethod(String key, String value){
        //entry in the hash map
        SecureMethodParam smp;
        smp = (SecureMethodParam)hm.get(key);
        if(smp==null) smp=new SecureMethodParam();
        if(value.equalsIgnoreCase("plain")){
          smp.secureMethod = SecureMethodParam.PLAIN;
        }else if(value.equalsIgnoreCase("sign")){
          smp.secureMethod = SecureMethodParam.SIGN;
        }else if(value.equalsIgnoreCase("encrypt")){
          smp.secureMethod = SecureMethodParam.ENCRYPT;
        }else if(value.equalsIgnoreCase("signAndEncrypt")){
          smp.secureMethod = SecureMethodParam.SIGNENCRYPT;
        }
        hm.put(key, smp);
    }
        
    private synchronized void updateSymmetricAlgorithm(String key, String value){
        //entry in the hash map
        SecureMethodParam smp;
        smp = (SecureMethodParam)hm.get(key);
        if(smp==null) smp=new SecureMethodParam();
        smp.symmSpec = value;
        hm.put(key, smp);
    }
    private synchronized void updateAsymmetricAlgorithm(String key, String value){
        //entry in the hash map
        SecureMethodParam smp;
        smp = (SecureMethodParam)hm.get(key);
        if(smp==null) smp=new SecureMethodParam();
        smp.asymmSpec = value;
        hm.put(key, smp);
    }
    private synchronized void updateSigningAlgorithm(String key, String value){
        //entry in the hash map
        SecureMethodParam smp;
        smp = (SecureMethodParam)hm.get(key);
        if(smp==null) smp=new SecureMethodParam();
        smp.signSpec = value;
        hm.put(key, smp);
    }
    
}
}
