/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
import org.cougaar.core.security.crypto.CertDirServiceRequestor;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.naming.CertificateEntry;
import org.cougaar.core.security.services.util.CACertDirectoryService;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CertificateDetailsServlet
  extends  HttpServlet
{
  //private ConfigParserService configParser = null;
  private LoggingService log;

  //private CertDirectoryServiceClient certificateFinder=null;
  private CACertDirectoryService search;
  //private CaPolicy caPolicy = null;            // the policy of the CA

  private SecurityServletSupport support;
  public CertificateDetailsServlet(SecurityServletSupport support) {
    this.support = support;
    log = (LoggingService)
      support.getServiceBroker().getService(this,
			       LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
  {
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {

    res.setContentType("text/html");
    String distinguishedName=null;
    String role=null;
    String cadnname=null;

    PrintWriter out=res.getWriter();

    if (log.isDebugEnabled()) {
      //log.debug("getContextPath:" + req.getContextPath());
      log.debug("getPathInfo:" + req.getPathInfo());
      log.debug("getPathTranslated:" + req.getPathTranslated());
      log.debug("getRequestURI:" + req.getRequestURI());
      log.debug("getServletPath:" + req.getServletPath());
    }

    distinguishedName=req.getParameter("distinguishedName");
    role=req.getParameter("role");
    cadnname=req.getParameter("cadnname");
    if (log.isDebugEnabled()) {
      log.debug("CertificateDetailsServlet. Search DN="
			 + distinguishedName
			 + " - role: " + role
			 + " - cadnname: " + cadnname);
    }
    if((cadnname==null)||(cadnname=="")) {
      out.print("Error in dn name ");
      out.flush();
      out.close();
      return;
    }
    /*
    try {
      configParser = (ConfigParserService)
	support.getServiceBroker().getService(this,
					      ConfigParserService.class,
					      null);
      caPolicy = configParser.getCaPolicy(cadnname);

      CertDirectoryServiceRequestor cdsr =
	new CertDirectoryServiceRequestorImpl(caPolicy.ldapURL, caPolicy.ldapType,
					      support.getServiceBroker(), cadnname);
      certificateFinder = (CertDirectoryServiceClient)
	support.getServiceBroker().getService(cdsr, CertDirectoryServiceClient.class, null);

    }
    catch (Exception e) {
      out.print("Unable to read policy file: " + e);
      out.flush();
      out.close();
      return;
    }
    */
    CertDirServiceRequestor cdsr =
      new CertDirServiceRequestor(support.getServiceBroker(), cadnname);
    search = (CACertDirectoryService)
      support.getServiceBroker().getService(cdsr, CACertDirectoryService.class, null);

    if((distinguishedName==null)||(distinguishedName=="")) {
      out.print("Error in distinguishedName ");
      out.flush();
      out.close();
      return;
    }

    /*
    String filter = "(uniqueIdentifier=" +distinguishedName + ")";
    LdapEntry[] ldapentries = certificateFinder.searchWithFilter(filter);
    if(ldapentries==null || ldapentries.length == 0) {
      out.println("Error: no such certificate in LDAP ");
      */
    // 
    CertificateEntry ce = search.findCertByIdentifier(distinguishedName);
    if (ce == null) {
      out.println("Error: no such certificate in cert directory ");
      out.flush();
      out.close();
      return;
    }

    X509Certificate  certimpl;
    certimpl=ce.getCertificate();

    String uri = req.getRequestURI();
    String certRevokeUri = uri.substring(0, uri.lastIndexOf('/')) + "/RevokeCertificateServlet";
    String downloadCertUri = null;
    if (DownloadCertificateServlet.isCA(certimpl.getSubjectDN().getName()) ||
        DownloadCertificateServlet.isUser(certimpl.getSubjectDN().getName())) {
      downloadCertUri = "DownloadCertificateServlet";
    }

    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Certificate details </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2> Certificate Details</H2>");
    out.println("<form name=\"revoke\" action=\"" +
		certRevokeUri + "\" method=\"post\">");
    out.println("<input type=\"hidden\" name=\"distinguishedName\" value=\""
		+ distinguishedName+"\">");
    if((role==null)||(role=="")) {
      if (log.isInfoEnabled()) {
	log.info("got role as null or empty in certificate details");
      }
    }
    else {
      out.println("<input type=\"hidden\" name=\"role\" value=\""+role+"\">");
    }
    out.println("<input type=\"hidden\" name=\"cadnname\" value=\""+cadnname+"\">");

    CertificateUtility.printCertificateDetails(out, certimpl);

    out.println("<input type=\"submit\" value=\"Revoke Certificate \">");
    out.println("</form>");
    if (downloadCertUri != null) {
      out.println("<form name=\"revoke\" action=\"" +
                  downloadCertUri + "\" method=\"post\">");
      out.println("<input type=\"hidden\" name=\"distinguishedName\" value=\""
                  + distinguishedName+"\">");
      out.println("<input type=\"hidden\" name=\"cadnname\" value=\""+
                  cadnname+"\">");
      out.println("<input type=\"submit\" value=\"Install Certificate \">");
      out.println("</form>");
    } // end of if (downloadCertUri != null)

    out.println("</body></html>");
    out.flush();
    out.close();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {

  }

  public String getServletInfo()  {
    return("Displaying details of certificate with give hash map");
  }

}
