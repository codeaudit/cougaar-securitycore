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


package org.cougaar.core.security.test.blackboard;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.monitoring.blackboard.CompromiseBlackboard;
import org.cougaar.core.security.test.AbstractServletComponent;
import org.cougaar.core.service.UIDService;


/**
 * Just simulates an sensor detecting a blackboard compromise and then
 * publishing a compromise object to the Blackboard. The only url parameter
 * is <i>scope<i> which is the scope of the compromise, either Agent, Node or Host
 *
 * @author ttschampel
 * @version $Revision: 1.3 $
 */
public class CompromiseBlackboardServlet extends AbstractServletComponent {
  private static final String SCOPE_PARAM="scope";
  /**
   * Path to servlet
   *
   * @return path to Servlet
   */
  protected String getPath() {
    return "/compromiseBlackboard";
  }


  /**
   * Just publish a compromise object to the blackboard
   *
   * @param request ServletRequest
   * @param response ServletResponse
   */
  protected void execute(HttpServletRequest request, HttpServletResponse response) {
    UIDService uidService = (UIDService) this.serviceBroker.getService(this, UIDService.class, null);

    //create BlackboardCompromise Object
    CompromiseBlackboard cb = new CompromiseBlackboard();
    cb.setTimestamp(System.currentTimeMillis());
    cb.setUID(uidService.nextUID());
    String scope = request.getParameter(SCOPE_PARAM);
    if(scope==null || scope.trim().length()==0){
    	if(logging.isWarnEnabled()){
    		logging.warn("No compromise scope in url query string, using agent scope!");
    	}
    	scope = CompromiseBlackboard.AGENT_COMPROMISE_TYPE;
    }
    cb.setCompromiseType(scope);
    this.blackboardService.openTransaction();
    this.blackboardService.publishAdd(cb);
    this.blackboardService.closeTransaction();
    if (logging.isDebugEnabled()) {
      logging.debug("Published CompromiseBlackboard Object");
    }
  }
}
