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
import javax.security.auth.x500.X500Principal;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.crypto.CertificateStatus;

import org.cougaar.core.security.certauthority.*;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.ldap.LdapEntry;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.services.identity.*;
import org.cougaar.core.security.services.crypto.*;

public class ListCaKeysServlet
  extends  HttpServlet
{
  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;
  private KeyRingService keyRingService= null;
  private LoggingService log;

  protected boolean debug = false;

  private SecurityServletSupport support;

  public ListCaKeysServlet(SecurityServletSupport support) {
    this.support = support;
    log = (LoggingService)
      support.getServiceBroker().getService(this,
					    LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
  {
    secprop = support.getSecurityProperties(this);
    debug = (Boolean.valueOf(secprop.getProperty(secprop.CRYPTO_DEBUG,
						"false"))).booleanValue();
    keyRingService = (KeyRingService)
      support.getServiceBroker().getService(this,
					    KeyRingService.class,
					    null);
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
  }
  
  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    res.setContentType("text/html");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>CA Keys List</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>CA Keys List</H2>");
    out.println("<table>");
    out.println("<form action=\"" + req.getRequestURI() + "\" method =\"post\">");

    Enumeration aliases = keyRingService.getAliasList();
    out.println("<table align=\"center\" border=\"2\">\n");
    out.println("<TR><TH> DN-Certificate </TH><TH> DN-Signed By </TH></TR>\n");

    while (aliases.hasMoreElements()) {
      String a = (String)aliases.nextElement();
      String cn = keyRingService.getCommonName(a);
      List certList = keyRingService.findCert(cn, KeyRingService.LOOKUP_KEYSTORE);
      Iterator it = certList.iterator();
      while (it.hasNext()) {
	X509Certificate c = ((CertificateStatus)it.next()).getCertificate();

	log.debug("alias=" + a + " - cn=" + cn);
	if (c != null) {
	  out.println("<TR>");
	  out.println("<TD>" + c.getSubjectDN().getName() +"</TD>\n" );
	  out.println("<TD>" + c.getIssuerDN().getName());
	  out.println("</TD></TR>\n");
	}
      }
    }
    out.println("</table>");
    out.flush();
    out.close();
    
  }
  
  public String getServletInfo()  {
    return("Generate a CA key");
  }
  
}
