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


import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewPrepositionalPhrase;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Verb;

import java.util.Vector;


/**
 * DOCUMENT ME!
 *
 * @author ttschampel
 */
public class BlackboardTestManagerServlet extends BaseServletComponent
  implements BlackboardClient {
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
  /** Cougaar BlackboardService */
  protected BlackboardService blackboardService;
  /** Cougaar Logging Service */
  protected LoggingService logging;
  /** Cougaar DomainService */
  protected DomainService domainService;

  /**
   * DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */
  protected String getPath() {
    return "/testBlackboardManager";
  }


  /**
   * DOCUMENT ME!
   */
  public void load() {
    this.serviceBroker = this.bindingSite.getServiceBroker();
    this.blackboardService = (BlackboardService) serviceBroker.getService(this,
        BlackboardService.class, null);
    this.logging = (LoggingService) serviceBroker.getService(this,
        LoggingService.class, null);
    this.domainService = (DomainService) serviceBroker.getService(this,
        DomainService.class, null);

    super.load();
  }


  /* (non-Javadoc)
   * @see org.cougaar.core.servlet.BaseServletComponent#createServlet()
   */
  protected Servlet createServlet() {
    // TODO Auto-generated method stub
    return new MyServlet();
  }


  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardClient#getBlackboardClientName()
   */
  public String getBlackboardClientName() {
    // TODO Auto-generated method stub
    return this.getClass().getName();
  }


  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardClient#currentTimeMillis()
   */
  public long currentTimeMillis() {
    // TODO Auto-generated method stub
    return 0;
  }

  private class MyServlet extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
      execute(request, response);
    }


    public void doPost(HttpServletRequest request, HttpServletResponse response) {
      execute(request, response);
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

      if (doParam != null) {
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

      }
    }
  }
}
