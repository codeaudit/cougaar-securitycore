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

package org.cougaar.core.security.certauthority.servlet;

import org.cougaar.core.security.certauthority.SecurityServletSupport;
import org.cougaar.core.security.services.util.ConfigParserService;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CaKeyManagement  extends HttpServlet {
  private ConfigParserService configParser = null;

  //private CaPolicy caPolicy = null;            // the policy of the CA

  private SecurityServletSupport support;
  public CaKeyManagement(SecurityServletSupport support) {
    this.support = support;
  }

  public void init(ServletConfig config) throws ServletException
    {
      configParser = (ConfigParserService)
        support.getServiceBroker().getService(this,
                                              ConfigParserService.class,
                                              null);
    }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
    {
      PrintWriter out=res.getWriter();

      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println("<title>Certificate Authority Key Management</title>");
      out.println("</head>");
      out.println("<body>");
      out.println("</body></html>");
      out.flush();
      out.close();
    }
  
  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
    {
      res.setContentType("text/html");
      PrintWriter out=res.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println("<title>Certificate Authority Key Management</title>");
      out.println("</head>");
      out.println("<body>");
      out.println("</body></html>");
      out.flush();
      out.close();
    }
  
  public String getServletInfo()
    {
      return("Manage keys of Certificate Authority");
    }
}
