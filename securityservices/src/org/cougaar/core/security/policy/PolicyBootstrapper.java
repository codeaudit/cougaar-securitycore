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


package org.cougaar.core.security.policy;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.builder.ParsedPolicy;
import org.cougaar.core.security.policy.builder.PolicyLexer;
import org.cougaar.core.security.policy.builder.PolicyParser;
import org.cougaar.core.security.policy.builder.ParsedPolicyFile;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.PolicyBootstrapperService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.util.ConfigFinder;

import java.io.IOException;
import java.io.Reader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import kaos.core.util.AttributeMsg;
import kaos.core.util.PolicyMsg;
import kaos.core.util.SubjectMsg;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;

public class PolicyBootstrapper 
  implements PolicyBootstrapperService
{

  private ServiceBroker serviceBroker;
  private ConfigParserService cps;
  private LoggingService log;
  private XMLPolicyCreator xpc;
  private XStream xstream = new XStream(new DomDriver());
  private static ParsedPolicyFile ppf;

  public static final String _damlBootPolicies = "OwlBootPolicyList";
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

  /**
   * Obtain the DAML Boot policies.
   *
   * It is interesting that this function logs but drops all errors.  Perhaps
   * a future version should throw the error to something that could take some 
   * action?
   */
  private void initDAMLPolicies()
  {
    _damlBootMap = new HashMap();

    ConfigFinder cf = ConfigFinder.getInstance();
    URL policyFileURL = null;
    List parsedPolicies;

    try {
      if (log.isDebugEnabled()) {
        log.debug(".PolicyBootStrapper: Reading daml policies file "
                + cf.find(_damlBootPolicies));
      }
      try {
        parsedPolicies = getParsedPolicyFile().policies();
      } catch (Exception e) { 
        if (log.isErrorEnabled()) {
          log.error("Unable to read policy file", e);
        }
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
        InputStream is = null;
        try {
          is = cf.open(fileName);
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

	if (is == null) {
          if (log.isErrorEnabled()) {
            log.error("Policy not found: " + fileName);
          }
          continue;
        }
        Reader reader = new InputStreamReader(is);

        PolicyMsg policy = (PolicyMsg)xstream.fromXML(reader);

        if (log.isDebugEnabled()) {
          log.debug(".PolicyBootStrapper: retrieved " + policy + 
                    "from the file " + policyFileURL);
        }
        Object lookup = _damlBootMap.get(type);
        if (lookup == null) { lookup = new Vector(); }
        List policyList = (List) lookup;
        policyList.add(policy);

        _damlBootMap.put(type, policyList);

        if (log.isDebugEnabled()) {
          log.debug("Got policy: " + parsedPolicy.getDescription());
        }
      }
    } catch (IOException e) {
      log.warn("Exception reading daml policies file", e);
    } catch (RuntimeException e) {
      log.warn("Exception reading daml policies file", e);
    }
    if (log.isDebugEnabled()) {
      log.debug(".PolicyBootStrapper: Finished Reading daml policies file");
    }
  }


  public boolean getDefaultModality()
  {
    return false;
  }


  public List getBootPolicies(String type)
  {
    List damlPolicies = (List) _damlBootMap.get(type);
    if (damlPolicies != null) {
      if (log.isDebugEnabled()) {
        log.debug(".PolicyBootStrapper: Obtained policies for policy type " + 
                type);
      }
      return damlPolicies;
    } else {
      if (log.isDebugEnabled()) {
        log.debug(".PolicyBootstrapper: attempting to get nondaml boot policies " +
                "for type " + type);
      }
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


  public static synchronized ParsedPolicyFile getParsedPolicyFile()
    throws IOException
  {
    if (ppf == null) {
      InputStream damlPoliciesFile = null;
      ConfigFinder cf = ConfigFinder.getInstance();

      damlPoliciesFile = cf.open(_damlBootPolicies);
      try {

        PolicyLexer  lexer  = new PolicyLexer(damlPoliciesFile);
        PolicyParser parser = new PolicyParser(lexer);
        ppf = parser.policyFile(); 
  
      } catch (Exception antlrException) {
        IOException ioe = new IOException();
        ioe.initCause(antlrException);
        throw ioe;
      } finally {
        damlPoliciesFile.close();
      }
    }
    return ppf;
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
