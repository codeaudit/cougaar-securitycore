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

package com.nai.security.certauthority;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.X509Certificate;
import sun.security.x509.*;

import com.nai.security.policy.CaPolicy;
import com.nai.security.crypto.ConfParser;
import com.nai.security.crypto.CertificateUtility;
import com.nai.security.crypto.ldap.CertDirectoryServiceClient;
import com.nai.security.crypto.ldap.CertDirectoryServiceFactory;
import com.nai.security.crypto.ldap.LdapEntry;

public class PendingCertDetailsServlet extends  HttpServlet
{
  private CertDirectoryServiceClient certificateFinder=null;
  private CaPolicy caPolicy = null;            // the policy of the CA

  protected boolean debug = false;
  javax.servlet.ServletContext context=null;

  public void init(ServletConfig config) throws ServletException
  {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    context=config.getServletContext();
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    res.setContentType("Text/HTML");

    String alias=null;
    String role=null;
    String cadnname=null;

    PrintWriter out=res.getWriter();

    if (debug) {
      //System.out.println("getContextPath:" + req.getContextPath());
      System.out.println("getPathInfo:" + req.getPathInfo());
      System.out.println("getPathTranslated:" + req.getPathTranslated());
      System.out.println("getRequestURI:" + req.getRequestURI());
      System.out.println("getServletPath:" + req.getServletPath());
    }

    alias=req.getParameter("alias");
    role=req.getParameter("role");
    cadnname=req.getParameter("cadnname");
    if (debug) {
      System.out.println("PendingCertDetailsServlet. Search alias="
			 + alias
			 + " - role: " + role
			 + " - cadnname: " + cadnname);
    }
    if((cadnname==null)||(cadnname=="")) {
      out.print("Error in dn name ");
      out.flush();
      out.close();
      return;
    }
    try {
      String confpath=(String)context.getAttribute("org.cougaar.security.crypto.config");
      ConfParser confParser = new ConfParser(confpath);
      caPolicy = confParser.readCaPolicy(cadnname, role);
      certificateFinder =
	CertDirectoryServiceFactory.getCertDirectoryServiceClientInstance(
				       caPolicy.ldapType, caPolicy.ldapURL);
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

      String certpath=(String)context.getAttribute("org.cougaar.security.CA.certpath");
      String confpath=(String)context.getAttribute("org.cougaar.security.crypto.config");

      PendingCertCache pendingCache = PendingCertCache.getPendingCache(cadnname, role, certpath, confpath);
      certimpl = (X509Certificate)pendingCache.getCertificate(
        caPolicy.pendingDirectory, alias);
    }
    catch (Exception exp) {
      out.println("error-----------  "+exp.toString());
      out.flush();
      out.close();
      return;
    }

    String uri = req.getRequestURI();
    String certApprovalUri = uri.substring(0, uri.lastIndexOf('/')) + "/processpending";

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
    if((role==null)||(role=="")) {
      if (debug) {
	System.out.println("got role as null or empty in certificate details:::::++++");
      }
    }
    else {
      out.println("<input type=\"hidden\" name=\"role\" value=\""+role+"\">");
    }
    out.println("<input type=\"hidden\" name=\"cadnname\" value=\""+cadnname+"\">");
    out.println("<p>");
    out.println("<p>");
    out.println("<b>Version&nbsp;&nbsp;&nbsp;:</b>"+certimpl.getVersion());
    out.println("<br>");
    out.println("<b>Subject&nbsp;&nbsp;&nbsp;:</b>"+certimpl.getSubjectDN().getName());
    out.println("<br>");
    out.println("<b>Signature Algorithm &nbsp;&nbsp;&nbsp;:</b>"+certimpl.getSigAlgName()+ ",<b>&nbsp;OID&nbsp; :</b>"+certimpl.getSigAlgOID());
    out.println("<br>");
    out.println("<b>Key&nbsp;&nbsp;&nbsp;:</b>"
		+ CertificateUtility.toHexinHTML(certimpl.getPublicKey().getEncoded()));
    out.println("<br>");
    out.println("<b>Validity&nbsp;&nbsp;&nbsp;:</b>");
    out.println("<br>");
    out.println("<b>&nbsp;&nbsp;&nbsp;From &nbsp;:</b>"+certimpl.getNotBefore().toString());
    out.println("<br>");
    out.println("<b>&nbsp;&nbsp;&nbsp;To &nbsp;:</b>"+certimpl.getNotAfter().toString());
    out.println("<br>");
    out.println("<b>Issuer&nbsp;&nbsp;&nbsp;:</b>"+certimpl.getIssuerDN().getName());
    out.println("<br>");
    out.println("<b>Serial No &nbsp;&nbsp;&nbsp;:</b>"+certimpl.getSerialNumber());
    out.println("<br>");
    out.println("<b>Algorithm&nbsp;&nbsp;&nbsp;:</b>"+certimpl.getPublicKey().getAlgorithm());
    out.println("<br>");
    out.println("<b>Signature &nbsp;&nbsp;&nbsp;:</b>"
		+ CertificateUtility.toHexinHTML(certimpl.getSignature()));
    out.println("<br>");
    out.println("<br>");
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





