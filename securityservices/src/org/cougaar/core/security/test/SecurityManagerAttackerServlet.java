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

import org.cougaar.core.service.LoggingService;
import org.cougaar.core.servlet.SimpleServletSupport;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SecurityManagerAttackerServlet
  extends  HttpServlet
{
  private LoggingService log;

  private SimpleServletSupport support;

  public void setSimpleServletSupport(SimpleServletSupport support) {
    this.support = support;
    log = (LoggingService) support.getLog();
  }

  public void init(ServletConfig config)
    throws ServletException
  {
  }

  public void doPost (HttpServletRequest req, HttpServletResponse res)
    throws ServletException,IOException
  {
    PrintWriter out=res.getWriter();
    String results = "";
    File f = null;
    boolean done = false;
    String fileName = "/etc/passwd";
    try {
      // Try to access a resource with having appropriate privileges
      f = new File(fileName);
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
    out.println("<H2>Java security manager exception generator</H2>");
    out.println("Results: " + fileName + ":" + results);
    out.println("</body></html>");
    out.flush();
    out.close();
  }
  
  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
  {
    res.setContentType("Text/HTML");
    PrintWriter out=res.getWriter();
    String uri=req.getRequestURI();

    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Java security manager exception generator</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Java security manager exception generator</H2>");

    out.println("<form action=\"" + uri + "\" method =\"post\">");
    out.println("Click on submit to generate a security manager exception &nbsp;");
    out.println("<input type=\"submit\">&nbsp;");
    out.println("<input type=\"reset\">");
    out.println("</form>");

    out.println("</body></html>");
    out.flush();
    out.close();
  }
  
  public String getServletInfo()
  {
    return("Attack the Java security manager");
  }
}
