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

package org.cougaar.core.security.crypto.servlet;

import org.cougaar.core.security.certauthority.SecurityServletSupport;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.security.GeneralSecurityException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MakeCertificateServlet
  extends  HttpServlet
{
  private SecurityServletSupport _support;
  private KeyRingService _keyRing;
  private LoggingService _log;

  public MakeCertificateServlet(SecurityServletSupport support) {
    _support = support;
    _log = (LoggingService)
      _support.getServiceBroker().getService(this,
					    LoggingService.class, null);
    _keyRing = (KeyRingService)
      _support.getServiceBroker().getService(this,
					    KeyRingService.class, null);
  }

  public void init(ServletConfig config)
    throws ServletException
  {
  }

  public void doPost (HttpServletRequest req, HttpServletResponse res)
    throws ServletException,IOException
  {
    String cname = req.getParameter("identifier");
    
    String msg = "Successfully requested new certificate for " + cname;
    if (cname != null) {
      try {
        _keyRing.addToIgnoredList(cname);
        // remove the entries first
        _keyRing.removeEntry(cname);
 
        // now force to get new certificates for this identifier
        _keyRing.checkOrMakeCert(cname);   
      } catch (Exception ex) {
        // should throw an IDMEF message
        if (ex instanceof GeneralSecurityException) {
          return;
        }
        msg = ex.toString();
      }          
    }
    else {
      msg = "no identifier provided, no action.";
    }

    res.setContentType("text/html");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Make new certificates </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Make new certificates </H2>");

    out.println(msg);

    out.println("</body></html>");
    out.flush();
    out.close();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
  }

  public String getServletInfo()  {
    return("For certificate expiry test cases, remove valid certificates and go request a expired one.");
  }

}
