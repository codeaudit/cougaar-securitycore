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

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

// Cougaar security services
import org.cougaar.core.security.certauthority.SecurityServletSupport;

public class Browser
  extends HttpServlet
{
  private SecurityServletSupport support;
  public Browser(SecurityServletSupport support) {
    this.support = support;
  }
 
  public void init(ServletConfig config) throws ServletException {
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    String uri = req.getRequestURI();
    String path = uri.substring(0, uri.lastIndexOf('/'));

    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html><head><title>Cougaar Certificate Authority</title></head>");
    out.println("<body>");
    // Certificate Signing requests
    out.println("<p><a href=\"" + path + "/CertificateSigningRequest\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>Request Certificate</b></big></a>");
    // Browser Certificate Signing requests
    out.println("<p><a href=\"" + path + "/BrowserSigningRequest\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>Request Browser Certificate</b></big></a>");
    // Certificate List
    out.println("<p><a href=\"" + path + "/CertificateList\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>Certificate List</b></big></a>");

    // Pending Certificate List
    out.println("<p><a href=\"" + path + "/PendingCertificateServlet\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>Pending Certificate List</b></big></a>");

    out.println("<p><big><font color=\"black\"><b>CA keys management</b></big></p>");
    out.println("<BLOCKQUOTE style=\"MARGIN-RIGHT: 0px\">");
    out.println("<p><a href=\"" + path + "/CreateCaKeyServlet\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>Create CA key</b></big></a></p>");
    out.println("<p><a href=\"" + path + "/ListCaKeysServlet\" target=\"mainwin\" >");
    out.println("<big><font color=\"blue\"><b>List CA keys</b></big></a></p>");
    out.println("</BLOCKQUOTE><p></body></html>");
    out.flush();
    out.close();
  }
  
  public String getServletInfo()  {
    return("Certificate Authority home");
  }
  
}
