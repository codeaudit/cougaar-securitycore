/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.X509Certificate;

import sun.security.x509.*;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.certauthority.*;

public class SecurityManagerAttackerServlet
  extends  HttpServlet
{
  private LoggingService log;

  private SecurityServletSupport support;
  public SecurityManagerAttackerServlet(SecurityServletSupport support) {
    this.support = support;
    log = (LoggingService)
      support.getServiceBroker().getService(this,
			       LoggingService.class, null);
  }

  public void init(ServletConfig config)
    throws ServletException
  {
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    PrintWriter out=res.getWriter();

    String results = "";
    File f = null;
    boolean done = false;
    try {
      // Try to access a resource with having appropriate privileges
      f = new File("/etc/passwd");
      done = f.delete();
      if (done) {
	results = " File was successfully deleted";
      }
      else {
	results = " File was NOT successfully deleted";
      }
    }
    catch (Exception e) {
      results = e.toString();
    }
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Java Security Manager attacker</title>");
    out.println("<script language=\"javascript\">");
    out.println("function submitme(form)");
    out.println("{ form.submit()}</script>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Java Security Manager attacke</H2>");

    out.println("Results: " + results);

    out.println("</body></html>");
    out.flush();
    out.close();
  }
  
  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
  {
    res.setContentType("Text/HTML");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Certificate List from Ldap </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Certificate List</H2>");

    out.println("<table>");
    out.println("<form action=\"\" method =\"post\">");
    out.println("<tr ><td colspan=\"3\">");
    out.println("</select>");
      
    // Table separators
    out.println(" <br> <br></td></tr>");
    out.println("<tr ><td colspan=\"3\">");
      
    out.println(" <br> <br></td></tr>");
    out.println("</tr><tr><td></td><td><br><input type=\"submit\">&nbsp;&nbsp;&nbsp;");
    out.println("<input type=\"reset\"></td><td></td></tr>");
    out.println("</form></table>");

    out.println("</body></html>");
    out.flush();
    out.close();
  }
  
  public String getServletInfo()
  {
    return("Attack the Java security manager");
  }
}
