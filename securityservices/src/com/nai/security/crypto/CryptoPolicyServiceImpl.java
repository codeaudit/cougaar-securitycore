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
import java.util.Set;
import java.util.Iterator;
import com.nai.security.policy.*;
import org.cougaar.planning.ldm.policy.*;
import com.nai.security.util.SecurityPropertiesService;
import org.cougaar.core.security.crypto.CryptoServiceProvider;

import safe.enforcer.NodeEnforcer;

public class CryptoPolicyServiceImpl implements CryptoPolicyService {

  private boolean dbg = false;
  private SecurityPropertiesService secprop = null;

    //policy source
    CryptoPolicyProxy cpp;

    //params look-up by name
  static HashMap send_hm = new HashMap();
  static HashMap receive_hm = new HashMap();

    /** Creates new CryptoPolicyServiceImpl */
    public CryptoPolicyServiceImpl() {
      // TODO. Modify following line to use service broker instead
      secprop = CryptoServiceProvider.getSecurityProperties();

      dbg = (Boolean.valueOf(secprop.getProperty(secprop.POLICY_DEBUG,
						"false"))).booleanValue();
      cpp = new CryptoPolicyProxy();
    }

    public synchronized SecureMethodParam getSendPolicy(String name) {
        String tag = name;
	Object obj = send_hm.get(tag);
	
        //if not found, try sender with default target
        if(obj==null) {
	    tag = name.substring(0, name.indexOf(':'))+":DEFAULT";
	    obj = send_hm.get(tag);
	}

        //if not found, try default sender with specified target
        if(obj==null) {
	    tag = "DEFAULT" + name.substring(name.indexOf(':'));
	    obj = send_hm.get(tag);
	}
		
        //still not found, last try with default sender and default target
        //usually the case at bootstrap
        if(obj==null) {
		tag = "DEFAULT:DEFAULT";
		obj = send_hm.get(tag);
	}

	if(dbg) {
	  System.out.println("CryptoPolicyService: outgoing policy for "
			     + tag);
	}
        return (SecureMethodParam)obj;
    }

    public synchronized SecureMethodParam getReceivePolicy(String name) {
	String tag = name;
        Object obj = receive_hm.get(tag);
        //if not found, try sender with default target
        if(obj==null) {
		tag = name.substring(0, name.indexOf(':'))+":DEFAULT";
		obj = receive_hm.get(tag);
	}
        //still not found, last try with default sender and default target
        //usually the case at bootstrap
        if(obj==null) {
		tag = "DEFAULT:DEFAULT";
		obj = receive_hm.get(tag);
	}
	
	if(dbg) {
	  System.out.println("CryptoPolicyService: incoming policy for "
			     + tag);
	}

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
      System.out.println("CryptoPolicyServiceImpl: Received policy message");
      RuleParameter[] param = policy.getRuleParameters();
      for (int i = 0 ; i < param.length ; i++) {
	System.out.println("Rule: " + param[i].getName() + " - " + param[i].getValue());
      }
    }

	if(policy == null)return;
        //whom is the policy for?
        String sub = policySubjectName;
        boolean isBoot = false;
        if(policyScope==""){
          isBoot = true;
          sub = "DEFAULT";
        }
        if(policyScope.equalsIgnoreCase("Domain") || policyScope.equalsIgnoreCase("VM")) {
          sub = "DEFAULT";
        }
        if(sub=="" || sub == null) return ;
	//String defaultRuleParam=null;
	String defaultInSymmetricAlg=null;
	String defaultOutSymmetricAlg=null;
	String defaultInAsymmetricAlg=null;
	String defaultOutAsymmetricAlg=null;
	String defaultOutSignAlg=null;
	String defaultInSignAlg=null;
	/*
	  booleans incomming and outgoing gives information to functions 
	  on which hash map to use  
	 */
	boolean incoming=true;
	boolean outgoing=false;
        //for each RuleParameter
	RuleParameter[] ruleParameters = policy.getRuleParameters();
        for (int j=0; j < ruleParameters.length; j++)
        {
            if(!(ruleParameters[j] instanceof KeyRuleParameter)) return;
            KeyRuleParameter krp = (KeyRuleParameter)ruleParameters[j];
            //process rules on all the parameters within secureMethodParam
            String name = krp.getName();
	    Object valueobj=krp.getValue();
	    String value=null;
	    if(valueobj!=null) {
	      value=(String)valueobj;
	      //defaultRuleParam=value; 
	    }
	    else {
	      if(dbg) {
		System.out.println("Warning : No default value for KeyRule parameter "); 
	      }
	    }
		
	    //    String value = (String)krp.getValue();
            KeyRuleParameterEntry[] entry = krp.getKeys();
            if(name.endsWith("SecureMethod")){
	      if(name.startsWith("Outgoing")) {
		if(value!=null) {
		  updateSecureMethod(sub+":"+"DEFAULT",value,outgoing);
		}
		for(int i = 0; i < entry.length; i++) {
		    String pair = entry[i].getKey();
		    //support for explicitly specify the whole pair.
		    if( pair.indexOf(':') < 0 )
			pair = sub+":"+pair;
		  updateSecureMethod(pair, entry[i].getValue(),outgoing);
		}
	      }
	      if(name.startsWith("Incoming")) {
		if(value!=null) { 
		  updateSecureMethod("DEFAULT"+":"+sub,value,incoming);
		}
		if(value!=null&&isBoot) {
		  updateSecureMethod("BOOT"+":"+sub,value,incoming);
		}
		for(int i = 0; i < entry.length; i++) {
		  updateSecureMethod(entry[i].getKey()+":"+sub, entry[i].getValue(),incoming);
		}
	      }
            }

            if(name.endsWith("SymmetricAlgorithm")){
	      if(name.startsWith("Outgoing")) {
		if(value!=null) {
		  defaultOutSymmetricAlg=value;
		  updateSymmetricAlgorithm(sub+":"+"DEFAULT",value,outgoing);
		}
		for(int i = 0; i < entry.length; i++) {
		  updateSymmetricAlgorithm(sub+":"+entry[i].getKey(), entry[i].getValue(),outgoing);
		}
	      }
	      if(name.startsWith("Incoming")) {
		if(value!=null) {
		  defaultInSymmetricAlg=value;
		  updateSymmetricAlgorithm("DEFAULT"+":"+sub,value,incoming);
		}
		if(value!=null&&isBoot) updateSymmetricAlgorithm("BOOT"+":"+sub,value,incoming);
		for(int i = 0; i < entry.length; i++) {
		  updateSymmetricAlgorithm(entry[i].getKey()+":"+sub, entry[i].getValue(),incoming);
		}
	      }
            }

            if(name.endsWith("AsymmetricAlgorithm")){
	      if(name.startsWith("Outgoing")) {
		if(value!=null) {
		  defaultOutAsymmetricAlg=value;
		  updateAsymmetricAlgorithm(sub+":"+"DEFAULT",value,outgoing);
		}
		for(int i = 0; i < entry.length; i++) {
		  updateAsymmetricAlgorithm(sub+":"+entry[i].getKey(), entry[i].getValue(),outgoing);
		}
	      }
	      if(name.startsWith("Incoming")) {
		if(value!=null) {
		  defaultInAsymmetricAlg=value;
		  updateAsymmetricAlgorithm("DEFAULT"+":"+sub,value,incoming);
		}
		if(value!=null&&isBoot) updateAsymmetricAlgorithm("BOOT"+":"+sub,value,incoming);
		for(int i = 0; i < entry.length; i++) {
		  updateAsymmetricAlgorithm(entry[i].getKey()+":"+sub, entry[i].getValue(),incoming);
		}
	      }
            }

            if(name.endsWith("SigningAlgorithm")){
	      if(name.startsWith("Outgoing")) {
		if(value!=null) {
		  defaultOutSignAlg=value;
		  updateSigningAlgorithm(sub+":"+"DEFAULT",value,outgoing);
		}
		for(int i = 0; i < entry.length; i++) {
		  updateSigningAlgorithm(sub+":"+entry[i].getKey(), entry[i].getValue(),outgoing);
		}
	      }
	      if(name.startsWith("Incoming")) {
		if(value!=null) {
		  defaultInSignAlg=value;
		  updateSigningAlgorithm("DEFAULT"+":"+sub,value,incoming);
		}
		if(value!=null&&isBoot) updateSigningAlgorithm("BOOT"+":"+sub,value,incoming);
		for(int i = 0; i < entry.length; i++) {
		  updateSigningAlgorithm(entry[i].getKey()+":"+sub, entry[i].getValue(),incoming);
		}
	      }
            }
	  }
	Set set=send_hm.keySet();
	Iterator iter=set.iterator();
	SecureMethodParam param=null;
	String key=null;
	
	for(;iter.hasNext();) {
	  key=(String)iter.next();
	  param=(SecureMethodParam)send_hm.get(key);
	  if((param.symmSpec==null)||(param.symmSpec.equals(""))) {
	    param.symmSpec=defaultOutSymmetricAlg;
	  }
	  if((param.asymmSpec==null)||(param.asymmSpec.equals(""))) {
	    param.asymmSpec=defaultOutAsymmetricAlg;
	  } 
	  if((param.signSpec==null)||(param.signSpec.equals(""))) {
	    param.signSpec=defaultOutSignAlg;
	  } 
	  send_hm.put(key,param);	 
	}
	set=receive_hm.keySet();
	iter=set.iterator();
	param=null;
	key=null;
	for(;iter.hasNext();) {
	  key=(String)iter.next();
	  param=(SecureMethodParam)receive_hm.get(key);
	  if((param.symmSpec==null)||(param.symmSpec.equals(""))) {
	    param.symmSpec=defaultInSymmetricAlg;
	  }
	  if((param.asymmSpec==null)||(param.asymmSpec.equals(""))) {
	    param.asymmSpec=defaultInAsymmetricAlg;
	  } 
	  if((param.signSpec==null)||(param.signSpec.equals(""))) {
	    param.signSpec=defaultInSignAlg;
	  } 
	  receive_hm.put(key,param);	 
	}
		       
      }

    private synchronized void updateSecureMethod(String key, String value,boolean incoming){
        //entry in the hash map
        SecureMethodParam smp;
	if(incoming) {
	  smp = (SecureMethodParam)receive_hm.get(key);
	}
	else {
	   smp = (SecureMethodParam)send_hm.get(key);
	}
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
	if(incoming) {
	  receive_hm.put(key, smp);
	}
	else {
	   send_hm.put(key, smp);
	}
    }

    private synchronized void updateSymmetricAlgorithm(String key, String value,boolean incoming){
        //entry in the hash map
        SecureMethodParam smp;
	if(incoming) {
	  smp = (SecureMethodParam)receive_hm.get(key);
	}
	else {
	   smp = (SecureMethodParam)send_hm.get(key);
	}
	// smp = (SecureMethodParam)hm.get(key);
        if(smp==null) smp=new SecureMethodParam();
        smp.symmSpec = value;
	if(incoming) {
	  receive_hm.put(key, smp);
	}
	else {
	   send_hm.put(key, smp);
	}
	// hm.put(key, smp);
    }
    private synchronized void updateAsymmetricAlgorithm(String key, String value, boolean incoming){
        //entry in the hash map
        SecureMethodParam smp;
	if(incoming) {
	  smp = (SecureMethodParam)receive_hm.get(key);
	}
	else {
	   smp = (SecureMethodParam)send_hm.get(key);
	}
        //smp = (SecureMethodParam)hm.get(key);
        if(smp==null) smp=new SecureMethodParam();
        smp.asymmSpec = value;
	if(incoming) {
	  receive_hm.put(key, smp);
	}
	else {
	   send_hm.put(key, smp);
	}
	// hm.put(key, smp);
    }
    private synchronized void updateSigningAlgorithm(String key, String value, boolean incoming){
        //entry in the hash map
        SecureMethodParam smp;
        if(incoming) {
	  smp = (SecureMethodParam)receive_hm.get(key);
	}
	else {
	   smp = (SecureMethodParam)send_hm.get(key);
	}
	//smp = (SecureMethodParam)hm.get(key);
        if(smp==null) smp=new SecureMethodParam();
        smp.signSpec = value;
	if(incoming) {
	  receive_hm.put(key, smp);
	}
	else {
	   send_hm.put(key, smp);
	}
	// hm.put(key, smp);
    }

}
}
