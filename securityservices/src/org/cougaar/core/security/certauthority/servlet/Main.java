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
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.crypto.CertificateCacheService;

public class Main
  extends HttpServlet
{
  private SecurityServletSupport support;
  //private ConfigParserService configParser = null;
  private KeyRingService keyRingService= null;
  private CertificateCacheService  cacheService=null;

  public Main(SecurityServletSupport support) {
    this.support = support;
  }
 
  public void init(ServletConfig config)
    throws ServletException
  {
    keyRingService = (KeyRingService)
      support.getServiceBroker().getService(this,
					    KeyRingService.class,
					    null);
     cacheService = (CertificateCacheService)
      support.getServiceBroker().getService(this,
					    CertificateCacheService.class,
					    null);
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html><head><title>Cougaar Certificate Authority</title></head>");

    out.println("<body><font face=\"arial black\" color=\"#3300cc\">");
    out.println("<h1>Cougaar Certificate Authority</h1></font>");
    out.println("<h2>Select action in left frame</h2>");

    Enumeration aliases = cacheService.getAliasList();
    if (!aliases.hasMoreElements()) {
      // No Ca key has been generated yet
      out.println("<br><br><b>WARNING!</b>");
      out.println("<br>At list one CA key must be generated before the CA can be used.");
      out.println("<br>Select \"Create CA key\" in the left frame.");
    }
    out.println("</body></html>");

    out.flush();
    out.close();
  }
  
  public String getServletInfo()  {
    return("Certificate Authority home");
  }
  
}
