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
import java.security.cert.X509Certificate;
import sun.security.x509.*;

import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.crypto.ldap.CertDirectoryServiceFactory;
import org.cougaar.core.security.crypto.ldap.LdapEntry;
import org.cougaar.core.security.certauthority.*;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

public class Index extends  HttpServlet
{
  private SecurityServletSupport support;
  public Index(SecurityServletSupport support) {
    this.support = support;
  }
 
  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html><head><title>Cougaar Certificate Authority</title></head>");
    out.println("<FRAMESET COLS=\"25%,75%\">");
    out.println("<FRAME name=\"nav\" SRC=\"Browser\">");
    out.println("<FRAME name=\"mainwin\" SRC=\"Main\">");
    out.println("</FRAMESET></html>");
    out.flush();
    out.close();
  }
  
  public String getServletInfo()  {
    return("Certificate Authority home");
  }
  
}
