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

package org.cougaar.core.security.dataprotection.plugin;

import org.cougaar.core.security.certauthority.SecurityServletSupport;
import org.cougaar.core.security.dataprotection.DataProtectionStatus;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PersistenceVerificationServlet
  extends  HttpServlet
{
  private SecurityServletSupport _support;
  private LoggingService _log;

  public PersistenceVerificationServlet(SecurityServletSupport support) {
    _support = support;
    _log = (LoggingService)
      _support.getServiceBroker().getService(this,
					    LoggingService.class, null);
  }

  public void init(ServletConfig config)
    throws ServletException
  {
  }

  public void doPost (HttpServletRequest req, HttpServletResponse res)
    throws ServletException,IOException
  {
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    String type = req.getParameter("type");
    if (type == null) {
      type = "BOTH";
    }

    res.setContentType("text/html");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Persistence Status </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Persistence Status </H2>");

    StringBuffer sb=new StringBuffer();

    if (!type.equals("INPUT")) {
      Hashtable h = DataProtectionStatus.getOutputStatus();
      sb.append("Output status:<br>\n");
      writeStatus(h, sb);
    }
    if (!type.equals("OUTPUT")) {
      sb.append("Input status:<br>\n");
      Hashtable h = DataProtectionStatus.getInputStatus();
      writeStatus(h, sb);
    }

    out.println(sb.toString());

    out.println("</body></html>");
    out.flush();
    out.close();
  }

  private void writeStatus(Hashtable h, StringBuffer sb) {
    sb.append("<table align=\"center\" border=\"2\">\n");
    sb.append("<TR><TH> Timestamp </TH><TH> Agent </TH><TH> Status </TH></TR>\n");
    for (Enumeration en = h.elements(); en.hasMoreElements(); ) {
      List statusList = (List)en.nextElement();
      for (int i = 0; i < statusList.size(); i++) {
        DataProtectionStatus status = (DataProtectionStatus)
          statusList.get(i);
        sb.append("<TR><TD>"+status.timestamp+"</TD>" );
        sb.append("<TD>"+status.agent+"</TD>" );
        sb.append("<TD>"+status.status+"</TD></TR>");
      }
    }
    sb.append("</table>");
  }

  public String getServletInfo()  {
    return("For test case verification, displays persistence times and status.");
  }

}
