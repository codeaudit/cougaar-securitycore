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

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.crypto.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.crypto.ldap.CertDirectoryServiceFactory;
import org.cougaar.core.security.crypto.ldap.LdapEntry;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.certauthority.*;

public class PendingCertDetailsServlet extends  HttpServlet
{
  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;
  private NodeConfiguration nodeConfiguration;
  private CertDirectoryServiceClient certificateFinder=null;
  private CaPolicy caPolicy = null;            // the policy of the CA
  protected boolean debug = false;
  private SecurityServletSupport support;
  private LoggingService log;

  public PendingCertDetailsServlet(SecurityServletSupport support) {
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
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    res.setContentType("Text/HTML");

    String alias=null;
    //String role=null;
    String cadnname=null;

    PrintWriter out=res.getWriter();

    if (debug) {
      //log.debug("getContextPath:" + req.getContextPath());
      log.debug("getPathInfo:" + req.getPathInfo());
      log.debug("getPathTranslated:" + req.getPathTranslated());
      log.debug("getRequestURI:" + req.getRequestURI());
      log.debug("getServletPath:" + req.getServletPath());
    }

    alias=req.getParameter("alias");
    //role=req.getParameter("role");
    cadnname=req.getParameter("cadnname");
    if (log.isDebugEnabled()) {
      log.debug("PendingCertDetailsServlet. Search alias="
		+ alias
		+ " - cadnname: " + cadnname);
    }
    if((cadnname==null)||(cadnname=="")) {
      out.print("Error in dn name ");
      out.flush();
      out.close();
      return;
    }
    try {
      configParser = (ConfigParserService)
	support.getServiceBroker().getService(this,
					      ConfigParserService.class,
					      null);
      caPolicy = configParser.getCaPolicy(cadnname);
      nodeConfiguration = new NodeConfiguration(cadnname,
						support.getServiceBroker());
    
      certificateFinder =
	CertDirectoryServiceFactory.getCertDirectoryServiceClientInstance(
				       caPolicy.ldapType, caPolicy.ldapURL,
				       support.getServiceBroker());
    }
    catch (Exception e) {
      out.print("Unable to read policy file: " + e);
      out.flush();
      out.close();
      return;
    }

    if((alias==null)||(alias=="")) {
      out.print("Error in alias ");
      out.flush();
      out.close();
      return;
    }

    X509Certificate  certimpl;
    try {

      PendingCertCache pendingCache =
	PendingCertCache.getPendingCache(cadnname,
					 support.getServiceBroker());
      certimpl = (X509Certificate)pendingCache.getCertificate(
        nodeConfiguration.getPendingDirectoryName(cadnname), alias);
    }
    catch (Exception exp) {
      out.println("error-----------  "+exp.toString());
      out.flush();
      out.close();
      return;
    }

    String uri = req.getRequestURI();
    String certApprovalUri = uri.substring(0, uri.lastIndexOf('/')) + "/ProcessPendingCertServlet";

    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Pending Certificate Request details </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2> Pending Certificate Request Details</H2><BR>");
    out.println("<form name=\"revoke\" action=\"" +
		certApprovalUri + "\" method=\"post\">");
    out.println("<input type=\"hidden\" name=\"alias\" value=\""
		+ alias+"\">");
    /*
    if((role==null)||(role=="")) {
      if (log.isDebugEnabled()) {
	log.debug("got role as null or empty in certificate details:::::++++");
      }
    }
    else {
      out.println("<input type=\"hidden\" name=\"role\" value=\""+role+"\">");
    }
    */
    out.println("<input type=\"hidden\" name=\"cadnname\" value=\""+cadnname+"\">");
    out.println("<p>");
    out.println("<p>");

    CertificateUtility.printCertificateDetails(out, certimpl);
   
    out.println("<br>");
    out.println("<input type=\"submit\" name=\"actiontype\" value=\"Approve Certificate \">");
    out.println("<input type=\"submit\" name=\"actiontype\" value=\"Deny Certificate \">");
    out.println("</form>");
    out.println("</body></html>");
    out.flush();
    out.close();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
  {

  }

  public String getServletInfo()
  {
    return("Displaying details of certificate with give hash map");
  }

}





