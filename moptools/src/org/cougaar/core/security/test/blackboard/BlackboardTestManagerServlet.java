/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


/*
 * Created on Jun 5, 2003
 *
 *
 */
package org.cougaar.core.security.test.blackboard;


import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Vector;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.test.AbstractServletComponent;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewPrepositionalPhrase;
import org.cougaar.planning.ldm.plan.PrepositionalPhrase;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.util.UnaryPredicate;


/**
 * DOCUMENT ME!
 *
 * @author ttschampel
 */
public class BlackboardTestManagerServlet extends AbstractServletComponent {
  /** DOCUMENT ME! */
  public static final String DO_PARAM = "do";
  /** DOCUMENT ME! */
  public static final String EXP_PARAM = "exp";
  /** DOCUMENT ME! */
  public static final String START_TESTING = "start";
  /** DOCUMENT ME! */
  public static final String END_TESTING = "end";
  /** DOCUMENT ME! */
  public static final String VERB = "BlackboardTestVerb";
  /** DOCUMENT ME! */
  public static final String STATUS = "STATUS";
  /** DOCUMENT ME! */
  public static final String EXP_NAME_PREP = "EXP_NAME";

  /* (non-Javadoc)
   * @see com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent#getPath()
   */
  protected String getPath() {
    // TODO Auto-generated method stub
    return "/testBlackboardManager";
  }


  /* (non-Javadoc)
   * @see com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent#execute(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
   */
  protected void execute(HttpServletRequest request,
    HttpServletResponse response) {
    // TODO Auto-generated method stub
    String doParam = request.getParameter(DO_PARAM);
    String expParam = request.getParameter(EXP_PARAM);
    if (logging.isDebugEnabled()) {
      logging.debug("BlackboardTestManagerServlet: " + doParam + " - "
        + expParam);
    }

    if (doParam != null && !(doParam.equals("isReady"))) {
      blackboardService.openTransaction();
      PlanningFactory pf = (PlanningFactory) domainService.getFactory(
          "planning");
      NewTask task = pf.newTask();
      task.setVerb(Verb.getVerb(VERB));
      Vector phrases = new Vector();
      NewPrepositionalPhrase npp = pf.newPrepositionalPhrase();
      npp.setIndirectObject(doParam);
      npp.setPreposition(STATUS);
      phrases.add(npp);

      NewPrepositionalPhrase expp = pf.newPrepositionalPhrase();
      expp.setPreposition(EXP_NAME_PREP);
      expp.setIndirectObject(expParam);
      phrases.add(expp);

      task.setPrepositionalPhrases(phrases.elements());

      blackboardService.publishAdd(task);
      blackboardService.closeTransaction();

    }else if(doParam!=null && doParam.equals("isReady")){
    	if(logging.isDebugEnabled()){
    		logging.debug("Checking if org activies ready");
    	}
    	blackboardService.openTransaction();
    	Collection c= blackboardService.query(new UnaryPredicate(){
    		public boolean execute(Object o){
    			return o instanceof OrgActivity;
    		}
    	});
	blackboardService.closeTransaction();

	PrintWriter out = null;
	try {
	  out = response.getWriter();
	} catch (IOException e) {
	  if(logging.isErrorEnabled()){
	    logging.error("Error writing ready result",e);
	  }
	}
    	
    	if(c.size()>0){
    		out.println("TRUE");	
    	
    	}else{
    		out.println("FALSE");
    	}
    	out.close();
    }
    else {
      // Status for real user invoking servlet
      if(logging.isDebugEnabled()){
	logging.debug("blackboard test status");
      }
      blackboardService.openTransaction();
      Collection c= blackboardService.query(new UnaryPredicate(){
	  public boolean execute(Object o){
	    return ((o instanceof Task) && ((Task)o).getVerb().equals(VERB));
	  }
    	});
      blackboardService.closeTransaction();
      PrintWriter out = null;
      try {
	out = response.getWriter();
	Iterator it = c.iterator();
	out.println("Blackboard check status - List of requests tasks on the blackboard:");
	for (int i = 0 ; it.hasNext() ; i++) {
	  Task t = (Task) it.next();
	  out.println("Request " + i);
	  Enumeration phrases = t.getPrepositionalPhrases();
	  while (phrases.hasMoreElements()) {
	    PrepositionalPhrase pp = (PrepositionalPhrase)phrases.nextElement();
	    out.println("  Indirect object: " + pp.getIndirectObject());
	  }
	}
      } catch (IOException e) {
	if(logging.isErrorEnabled()){
	  logging.error("Error writing ready result",e);
	}
      }
      finally {
	if (out != null) {
	  out.close();
	}
      }
    }
  }
}
