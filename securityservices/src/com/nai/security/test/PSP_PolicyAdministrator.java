/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
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

package com.nai.security.test;

import KAoS.KPAT.tunnel.*;
import KAoS.KPAT.message.*;
import KAoS.Util.Msg;
import KAoS.Policy.PolicyConstants;
import SAFE.PolicyManager.*;
import SAFE.Util.*;

import org.w3c.dom.Document;
import org.cougaar.util.ConfigFinder;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.cluster.*;
import org.cougaar.domain.planning.ldm.plan.*;
import org.cougaar.lib.planserver.*;
import com.nai.security.util.*;

import java.io.*;
import java.util.*;
import java.text.SimpleDateFormat;
import java.io.ObjectInputStream;

/**
 * A Cougaar predicate to match PolicyMsg objects
 */
class PolicyMsgPredicate implements UnaryPredicate {
  public boolean execute(Object o) {
    return o instanceof PolicyMsg;
  }
}

public class PSP_PolicyAdministrator extends PSP_BaseAdapter implements PlanServiceProvider, UISubscriber {

  /** A zero-argument constructor is required for dynamically loaded PSPs,
   *         required by Class.newInstance()
   **/
  public PSP_PolicyAdministrator()
  {
    super();
  }    

  /**
   * Some PSPs can respond to queries -- URLs that start with "?"
   * I don't respond to queries
   */
  public boolean test(HttpInput query_parameters, PlanServiceContext sc)
  {
    super.initializeTest(); // IF subclass off of PSP_BaseAdapter.java
    return false;  // This PSP is only accessed by direct reference.
  }
	

  /**
   * Called when a HTTP request is made of this PSP.
   * @param out data stream back to the caller.
   * @param query_parameters tell me what to do.
   * @param psc information about the caller.
   * @param psu unused.
   */
  public void execute( PrintStream out,
		       HttpInput query_parameters,
		       PlanServiceContext psc,
		       PlanServiceUtilities psu ) throws Exception {

    out.println("PolicyAdmin: execute<p>");
    // BEGIN TEMPORARY CODE
    // temporary code which publishes a hard-coded policy message
    Vector v = query_parameters.getParameterTokens("",'_');		
    if (v != null) {
      int index = 0;
      String scope = (String) v.elementAt(index++);
      String domain = (String) v.elementAt(index++);
      String host = null;
      String vm = null;
      String agent = null;
      if (!scope.equalsIgnoreCase("Domain")) {
	host = (String) v.elementAt(index++);
	vm = (String) v.elementAt(index++);
				
	if (!scope.equalsIgnoreCase("Node")) {
	  agent = (String) v.elementAt(index++);
	}
      }
      String subjectId = (String) v.elementAt(index++);
      String targetId = (String) v.elementAt(index++);
      String policyType = (String) v.elementAt(index++);
      String xmlFilename = (String) v.elementAt(index++);

      HashMap hashmap = new HashMap();
      ConfigFinder configFinder = new ConfigFinder();
      File f = configFinder.locateFile(xmlFilename);
      Document doc = null;
      if (f != null) {
	doc = configFinder.parseXMLConfigFile(f.getPath());
      }
      if (doc == null) {
	out.println("Unable to parse XML file<p>");
      }
      out.println("Document:<p>");
      DOMWriter XMLdebug = new DOMWriter(out);
      XMLdebug.print(doc);

      hashmap.put("XMLContent", doc);

      Msg policy = KAoSPolicyMessage.createPolicy("",
						  "",
						  "",
						  scope,
						  "",
						  subjectId,
						  "",
						  targetId,
						  policyType,
						  hashmap);
      out.println("Scope: " + scope + "<p>");
      out.println("SubjectID: " + subjectId + "<p>");
      out.println("targetID: " + targetId + "<p>");
      out.println("policyType: " + policyType + "<p>");
      out.println("xmlFilename: " + xmlFilename + "<p>");
      out.println("xmlFilePath: " + f.getPath() + "<p>");
      out.println("Policy: " + policy + "<p>");

      Collection policyMsgs = psc.getServerPlugInSupport().queryForSubscriber(new PolicyMsgPredicate());
      // this should be OK since there should be only 1 policy message on the blackboard at a time
      PolicyMsg msg = (PolicyMsg) policyMsgs.iterator().next();
      if (scope.equalsIgnoreCase("Domain")) {
	msg.addPolicyForDomain(domain,
			       policy);
      }
      else if (scope.equalsIgnoreCase("Node")) {
	msg.addPolicyForVM(domain,
			   host,
			   vm,
			   policy);
      }
      else if (scope.equalsIgnoreCase("Agent")) {
	msg.addPolicyForAgent(domain,
			      host,
			      vm,
			      agent,
			      policy);
      }
			
      UnexpandedPolicyMsg upm = new UnexpandedPolicyMsg(msg);
      psc.getServerPlugInSupport().publishAddForSubscriber(upm);
									
    }		
    else {
      // END TEMPORARY CODE
      try {        
	ByteArrayInputStream bais = new ByteArrayInputStream(query_parameters.getBody());
	ObjectInputStream in = new ObjectInputStream(bais);
	// the first integer of the message represents the function name
	int ordinal = in.readInt();
	// the tunnel client writes another integer to separate the function name from
	// any parameters, so read it in and discard it
	int separator = in.readInt();
			
	if (ordinal == TunnelServlet.ORDINAL_SET_POLICY_MSG) {
	  Object message = in.readObject();
	  if (message instanceof PolicyMsg) {
	    UnexpandedPolicyMsg upm = new UnexpandedPolicyMsg((PolicyMsg) message);
	    psc.getServerPlugInSupport().publishAddForSubscriber(upm);
	    System.out.println("Successfully published UnexpandedPolicyMsg");
	  }
	  else if (message instanceof ConditionalPolicyMsg) {
	    UnexpandedConditionalPolicyMsg ucpm = new UnexpandedConditionalPolicyMsg((ConditionalPolicyMsg) message);
	    psc.getServerPlugInSupport().publishAddForSubscriber(ucpm);
	    System.out.println("Successfully published UnexpandedConditionalPolicyMsg");
	  }
	  else {
	    System.err.println("Error: unrecognized message type in Policy Administrator");
	  }
	}
	else if (ordinal == TunnelServlet.ORDINAL_GET_POLICY_MSG) {
	  Collection policyMsgs = psc.getServerPlugInSupport().queryForSubscriber(new PolicyMsgPredicate());
				// this should be OK since there should be only 1 policy message on the blackboard at a time
	  PolicyMsg msg = (PolicyMsg) policyMsgs.iterator().next();
				
				// not sure if this will work, I'm not too familiar with output streams
	  ByteArrayOutputStream baos = new ByteArrayOutputStream();
	  ObjectOutputStream out2 = new ObjectOutputStream(baos);

				// or this???
	  out2.writeObject(msg);
	  out.write(baos.toByteArray());
	  out.flush();

	}
	else {
	  System.err.println("Error: undefined ordinal in Policy Administrator message");
	}
      }
      catch (Exception ex) {
	out.println(ex.getMessage());
	ex.printStackTrace(out);
	System.out.println(ex);
	out.flush();
      }
    }
  }  
	
  /**
   * A PSP can output either HTML or XML (for now).  The server
   * should be able to ask and find out what type it is.
   **/
  public boolean returnsXML() {
    return false;
  }
	
  public boolean returnsHTML() {
    return true;
  }
	
  /**  Any PlanServiceProvider must be able to provide DTD of its
   *  output IFF it is an XML PSP... ie.  returnsXML() == true;
   *  or return null
   **/
  public String getDTD()  {
    return null;
  }
	
  /**
   * The UISubscriber interface. (not needed)
   */
  public void subscriptionChanged(Subscription subscription) {
  }  
}
