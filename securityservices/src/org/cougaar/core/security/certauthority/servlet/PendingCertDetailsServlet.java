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

import org.cougaar.core.security.certauthority.PendingCertCache;
import org.cougaar.core.security.certauthority.SecurityServletSupport;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.NodeConfiguration;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PendingCertDetailsServlet
  extends HttpServlet
{
  private NodeConfiguration nodeConfiguration;
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
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    res.setContentType("text/html");

    String alias=null;
    //String role=null;
    String cadnname=null;

    PrintWriter out=res.getWriter();

    if (log.isDebugEnabled()) {
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





