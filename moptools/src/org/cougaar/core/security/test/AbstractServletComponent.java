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
 * Created on Jun 6, 2003
 *
 *
 */
package org.cougaar.core.security.test;


import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.servlet.BaseServletComponent;


/**
 * Servlet that creates csv and HTML format
 *
 * @author ttschampel
 */
public abstract class AbstractServletComponent extends BaseServletComponent
  implements BlackboardClient {
  /** Cougaar BlackboardService */
  protected BlackboardService blackboardService;
  /** Cougaar Logging Service */
  protected LoggingService logging;
  /** Cougaar DomainService */
  protected DomainService domainService;
  protected Object parameter;

  /* (non-Javadoc)
   * @see com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent#getPath()
   */
  protected abstract String getPath();


  /* (non-Javadoc)
   * @see com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent#execute(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
   */
  protected abstract void execute(HttpServletRequest request,
    HttpServletResponse response);


  /* (non-Javadoc)
   * @see org.cougaar.core.servlet.BaseServletComponent#createServlet()
   */
  protected Servlet createServlet() {
    return new MyServlet();
  }


  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardClient#getBlackboardClientName()
   */
  public String getBlackboardClientName() {
    // TODO Auto-generated method stub
    return null;
  }


  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardClient#currentTimeMillis()
   */
  public long currentTimeMillis() {
    // TODO Auto-generated method stub
    return 0;
  }


  /**
   * Called just after construction (via introspection) by the  loader if a
   * non-null parameter Object was specified by the ComponentDescription.
   *
   * @param param DOCUMENT ME!
   */
  public void setParameter(Object param) {
    parameter = param;
  }


  /**
   * DOCUMENT ME!
   *
   * @return the parameter set by {@link #setParameter}
   */
  public Object getParameter() {
    return parameter;
  }


  /**
   * Get any Component parameters passed by the instantiator.
   *
   * @return The parameter specified if it was a collection, a collection with
   *         one element (the parameter) if  it wasn't a collection, or an
   *         empty collection if the parameter wasn't specified.
   */
  public Collection getParameters() {
    if (parameter == null) {
      return new ArrayList(0);
    } else {
      if (parameter instanceof Collection) {
        return (Collection) parameter;
      } else {
        List l = new ArrayList(1);
        l.add(parameter);
        return l;
      }
    }
  }

  private class MyServlet extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
      execute(request, response);
    }


    public void doPost(HttpServletRequest request, HttpServletResponse response) {
      execute(request, response);
    }
  }
}
