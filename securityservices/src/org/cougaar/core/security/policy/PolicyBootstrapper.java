/**
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
 * Created on September 19, 2001, 2:38 PM
 */

package org.cougaar.core.security.policy;

import java.util.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.URL;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.util.ConfigFinder;
import org.cougaar.planning.ldm.policy.Policy;

// Cougaar security services
import org.cougaar.core.security.policy.builder.ParsedPolicy;
import org.cougaar.core.security.policy.builder.PolicyParser;
import org.cougaar.core.security.policy.builder.PolicyLexer;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.PolicyBootstrapperService;
import org.cougaar.core.security.config.ConfigParserServiceImpl;

//from kaos
import kaos.core.util.*;

public class PolicyBootstrapper 
  implements PolicyBootstrapperService
{

  private ServiceBroker serviceBroker;
  private ConfigParserService cps;
  private LoggingService log;
  private XMLPolicyCreator xpc;

  private String _damlBootPolicies = "DamlBootPolicyList";
  private HashMap _damlBootMap;

  static String policyPath =
    System.getProperty("org.cougaar.core.security.BootPolicy",
		       "BootPolicy.ldm.xml");
 
  public PolicyBootstrapper(ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    if (log.isDebugEnabled()) {
      log.debug("Initializing Policy bootstrapper");
    }

    cps = (ConfigParserService)
      serviceBroker.getService(this,
			       ConfigParserService.class,null);
    
    //absolutely required.
    if (cps == null) {
      throw new RuntimeException(
                  "PolicyBootstrapper failed to get ConfigParserService.");
    }

    xpc = new XMLPolicyCreator(policyPath, 
                               ConfigFinder.getInstance(), 
                               "PolicyBootstrapper");

    if (xpc == null && log.isWarnEnabled()) {
      log.warn("Cannot get XML policy creator instance");
    }
    initDAMLPolicies();
  }

  private void initDAMLPolicies()
  {
    _damlBootMap = new HashMap();

    ConfigFinder cf = ConfigFinder.getInstance();
    InputStream damlPoliciesFile = null;
    InputStream policyStream = null;
    URL policyFileURL = null;

    try {
      String line;

      log.debug(".PolicyBootStrapper: Reading daml policies file "
                + cf.find(_damlBootPolicies));
      try {
        damlPoliciesFile = cf.open(_damlBootPolicies);
      } catch (IOException e) {
        log.fatal("Error opening the daml boot policies file" 
                  + _damlBootPolicies, e);
        throw e;
      }
      PolicyLexer lexer = new PolicyLexer(damlPoliciesFile);
      PolicyParser parser = new PolicyParser(lexer);
      List parsedPolicies;
      try {
        parsedPolicies = parser.policies();
      } catch (Exception e) { 
        throw new RuntimeException("Fatal", e);
      }
      for (Iterator parsedPoliciesIt = parsedPolicies.iterator();
           parsedPoliciesIt.hasNext();) {
        ParsedPolicy parsedPolicy = (ParsedPolicy) parsedPoliciesIt.next();
        String type     = parsedPolicy.getAction();
        String fileName = parsedPolicy.getPolicyName() + ".info";
        if (log.isDebugEnabled()) {
          log.debug("using grammar");
          log.debug("working on the file " + fileName);
        }
        try {
          policyStream = cf.open(fileName);
        } catch (IOException e) {
          if (log.isWarnEnabled()) {
            log.warn("policy  file " + fileName + " not loaded");
          }
          throw e;
        }
        if (log.isDebugEnabled()) {
          log.debug(".PolicyBootStrapper: for policy type " + type +
                    " I am looking in the policy file " + fileName);
        }

	if (policyStream == null) {
          if (log.isErrorEnabled()) {
            log.error("Policy not found: " + fileName);
          }
          continue;
        }

        ObjectInputStream policyObjectStream 
          = new ObjectInputStream(policyStream);
        PolicyMsg policy = (PolicyMsg) policyObjectStream.readObject();
        policyObjectStream.close();
        if (log.isDebugEnabled()) {
          log.debug(".PolicyBootStrapper: retrieved " + policy + 
                    "from the file " + policyFileURL);
        }
        Object lookup = _damlBootMap.get(type);
        if (lookup == null) { lookup = new Vector(); }
        List policyList = (List) lookup;
        policyList.add(policy);

        _damlBootMap.put(type, policyList);
      }
      damlPoliciesFile.close();
    } catch (IOException e) {
      log.warn("Exception reading daml policies file", e);
    } catch (ClassNotFoundException e) {
      log.error("Policy file " + policyFileURL + 
                " does not contain PolicyMsg object!", e);
    } catch (RuntimeException e) {
      log.warn("Exception reading daml policies file", e);
    }
    log.debug(".PolicyBootStrapper: Finished Reading daml policies file " 
              + damlPoliciesFile);
  }


  public boolean getDefaultModality()
  {
    return false;
  }


  public List getBootPolicies(String type)
  {
    List damlPolicies = (List) _damlBootMap.get(type);
    if (damlPolicies != null) {
      log.debug(".PolicyBootStrapper: Obtained policies for policy type " + 
                type);
      return damlPolicies;
    } else {
      log.debug(".PolicyBootstrapper: attempting to get nondaml boot policies " +
                "for type " + type);
      try {
        if (!type.startsWith("http:")) {
          PolicyMsg msg = getBootPolicy(Class.forName(type));
          Vector msgs = new Vector();
          msgs.add(msg);
          return msgs;
        }
      } catch (Throwable th) {
        log.error("Exception getting non-daml policies", th);
      }
    }
    return new Vector();
  }
  
  public synchronized PolicyMsg getBootPolicy(Class type)
  {
    if (log.isDebugEnabled()) {
      log.debug("getBootPolicy: " + type.getName());
    }
    Policy[] ruleParamPolicies = null;
    SecurityPolicy[] policies = null;

    Object obj = null;
    try{  
      obj = type.newInstance();
    } catch(Exception e) {
      if(log.isDebugEnabled())
	log.debug("getBootPolicy: invalid type specification--"
		  + e.getMessage());
    }
      
    if ( obj instanceof SecurityPolicy) {
      policies = cps.getSecurityPolicies(type);
    }
    else if ( obj instanceof Policy) {
      if(xpc!=null) {
        ruleParamPolicies = xpc.getPoliciesByType(type.getName());
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("getBootPolicy: " + type.getName()
	+ " - " + (policies == null ? 0 : policies.length) + " Security policies - "
	+ (ruleParamPolicies == null ? 0 : ruleParamPolicies.length) +
	" rule parameters policies");
    }

    PolicyMsg policyMsg = null;
    SubjectMsg sm = new SubjectMsg("bootID","default","scope");
    Vector v = new Vector();
    v.add(sm);
    policyMsg = new PolicyMsg ("boot",
       "BootPolicy",
       "boot policy",
       type.toString(),
       "admin",
       v,
       false);
    if (ruleParamPolicies != null) {
      for (int i=0; i<ruleParamPolicies.length; i++) {                    
        // wrap the policy in a KAoS message
        AttributeMsg attribMsg = new AttributeMsg("POLICY_OBJECT",
                                                  ruleParamPolicies[i],
                                                  true);
        policyMsg.setAttribute(attribMsg);
      }
    } 
    if (policies != null) {
      for (int i=0; i<policies.length; i++) {                    
        // wrap the policy in a KAoS message
        AttributeMsg attribMsg = new AttributeMsg("POLICY_OBJECT",
                                                  policies[i],
                                                  true);
        policyMsg.setAttribute(attribMsg);
      }
    } 
    if (log.isDebugEnabled()) {
      log.debug("getBootPolicy -- done! " + type.getName());
    }
    return policyMsg;
  }
}
