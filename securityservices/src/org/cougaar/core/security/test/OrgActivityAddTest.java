/*
 * <copyright>
 *  Copyright 1997-2001 Cougaar Software, Inc.
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
package org.cougaar.core.security.test;

import java.io.*;
import java.lang.*;
import java.util.*;
import java.security.*;

import javax.security.auth.*;
import javax.servlet.*;
import javax.servlet.http.*;

import org.cougaar.core.blackboard.*;
import org.cougaar.core.component.*;
import org.cougaar.core.plugin.*;
import org.cougaar.core.service.*;
import org.cougaar.core.util.*;
import org.cougaar.util.*;

import org.cougaar.core.security.services.auth.*;
import org.cougaar.core.security.auth.*;

import org.cougaar.glm.ldm.oplan.*;

public class OrgActivityAddTest extends ComponentPlugin
{
  private IncrementalSubscription _sub;
  private Servlet _servlet;
  private final String _servletPath = "/OrgActivityAdd";
  private ServletService _servletService = null;

  private UIDService _uidSrv = null;
  private BlackboardService _bbs = null;
  private LoggingService _log = null;
    
  private UnaryPredicate ORGACTIVITY_PRED = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        return (o instanceof OrgActivity);
      }
    };

  
  public void setParameter(Object params) {
    List l = (List)params;
    Iterator i = l.iterator();
    for(int x = 0; i.hasNext(); x++) {
      System.out.println("item(" + x + ") = " + i.next());
    }
  }

  protected void setupSubscriptions() {
    ServiceBroker sb = getServiceBroker();
    _log = (LoggingService)sb.getService(this, LoggingService.class, null);
    _bbs = getBlackboardService();
    _uidSrv = (UIDService)sb.getService(this, UIDService.class, null);
    _servletService = (ServletService)
      sb.getService(this,
                     ServletService.class,
                     null);
    if (_servletService == null) {
      throw new IllegalStateException("Unable to obtain ServletService");
    }
    _log.debug("<p>subscribing to OrgActivity</p>");
    _sub = (IncrementalSubscription)_bbs.subscribe(ORGACTIVITY_PRED);

    try {
      _servlet = new OrgActivityAddServlet();
      _servletService.register(_servletPath, _servlet);
    } catch (Exception e) {
      RuntimeException fatal 
        = new RuntimeException("Couldn't register servlet");
      fatal.initCause(e);
      throw fatal;
    }
  }

  public void execute() {
    // do nothing
    if(_sub.hasChanged()) {
      Collection c = _sub.getRemovedCollection();
      if(!c.isEmpty()) {
        _log.debug("############### OrgActivity removed ################"); 
        printOrgActivity(new LogWriter(),
                         (OrgActivity)c.iterator().next());
      } 
    }
  }
    
  private void printOrgActivity(Writer w, OrgActivity oa) 
  {
    try {
      w.write("<p>OrgActivity object: " + oa + "</p>");
      w.write("<p>OrgActivity name: " + oa.getActivityName() + "</p>");
      w.write("<p>OrgActivity type: " + oa.getActivityType() + "</p>");
      w.write("<p>OrgActivity id: " + oa.getOrgID() + "</p>");
    } catch (IOException e) {
      e.printStackTrace();
      _log.error("Error writing output", e);
    }
  }

  private class OrgActivityAddServlet extends HttpServlet
  {
    public void doGet(HttpServletRequest req,
                      HttpServletResponse res)
      throws IOException
    {
      PrintWriter out = res.getWriter();
      out.print("<html>\n" + 
                "<head>\n" + 
                "<TITLE>Blackboard Tests</TITLE>\n" + 
                "</head>\n" + 
                "<body>\n" + 
                "<H1>Add to Blackboard Enforcement Check</H1>\n");
      out.print("<p>Opening blackboard transaction.</p>");
      _bbs.openTransaction();
      OrgActivityImpl _orgActivity = null;
      try {
        out.print("<p>creating OrgActivity</p>");
        UID uid = _uidSrv.nextUID();
        // should check the create permission for OrgActivity
        _orgActivity = OplanFactory.newOrgActivity("NEW-test-type",
                                                   "NEW-test-name",
                                                   "NEW-test-id", 
                                                   uid);
        _orgActivity.setUID(uid);
        _orgActivity.setOwner(getAgentIdentifier());
        out.print("<p>publish add OrgActivity</p>");
        _bbs.publishAdd(_orgActivity);
        printOrgActivity(out,_orgActivity);
      } catch (Exception e) {
        out.print("<p>Exception caught:");
        e.printStackTrace(out);
        out.print("</p>");
      } finally {
        _bbs.closeTransaction();
      }
    }
  }

  private class LogWriter extends Writer
  {
    public void close() { ; }
    public void flush() { ; }
    public void write(char carray[], int length, int offset)
    {
      StringWriter sw = new StringWriter();
      sw.write(carray, length, offset);
      _log.debug(sw.toString());
    }
  }
}
