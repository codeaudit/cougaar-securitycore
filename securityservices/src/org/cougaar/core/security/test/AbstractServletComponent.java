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
import org.cougaar.util.log.LoggerFactory;


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
	private static org.cougaar.util.log.Logger auditLogger = LoggerFactory.getInstance().createLogger(AbstractServletComponent.class);
 
/**
 * Return the path to this servlet
 */
  protected abstract String getPath();


 /**
  * Execute the business logic here
  * @param request ServletRequest
  * @param response ServletResponse
  */
  protected abstract void execute(HttpServletRequest request,
    HttpServletResponse response);

  /**
   * Method implementation for blackboard clietn
   */
  protected Servlet createServlet() {
    return new MyServlet();
  }


 /**
  * Method implementation for Blackboard Client
  */
  public String getBlackboardClientName() {
    return this.getClass().getName();
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
   * DOCUMENT ME!
   */
  public void load() {
		super.load();
    this.serviceBroker = this.bindingSite.getServiceBroker();
    this.blackboardService = (BlackboardService) serviceBroker.getService(this,
        BlackboardService.class, null);
    if (auditLogger.isDebugEnabled()) {
      auditLogger.debug("Getting logging service...");
    }
    this.logging = (LoggingService) serviceBroker.getService(this,
        LoggingService.class, null);
    if (auditLogger.isDebugEnabled()) {
      auditLogger.debug("Logging service:" + logging);
    }
    this.domainService = (DomainService) serviceBroker.getService(this,
        DomainService.class, null);

   
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
