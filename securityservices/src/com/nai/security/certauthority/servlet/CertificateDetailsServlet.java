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

package com.nai.security.certauthority.servlet;

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
import com.nai.security.certauthority.*;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

public class CertificateDetailsServlet extends  HttpServlet
{
  private SecurityPropertiesService secprop = null;

  private CertDirectoryServiceClient certificateFinder=null;
  private CaPolicy caPolicy = null;            // the policy of the CA
  
  protected boolean debug = false;

  private SecurityServletSupport support;
  public CertificateDetailsServlet(SecurityServletSupport support) {
    this.support = support;
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
    String distinguishedName=null;
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

    distinguishedName=req.getParameter("distinguishedName");
    role=req.getParameter("role");
    cadnname=req.getParameter("cadnname");
    if (debug) {
      System.out.println("CertificateDetailsServlet. Search DN="
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
    try {
      String confpath=secprop.getProperty(secprop.CRYPTO_CONFIG);
      ConfParser confParser = new ConfParser(confpath, true);
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
    
    if((distinguishedName==null)||(distinguishedName=="")) {
      out.print("Error in distinguishedName ");
      out.flush();
      out.close();
      return;
    }
 
    String filter = "(uniqueIdentifier=" +distinguishedName + ")";
    LdapEntry[] ldapentries = certificateFinder.searchWithFilter(filter);
    if(ldapentries==null || ldapentries.length == 0) {
      out.println("Error: no such certificate in LDAP ");
      out.flush();
      out.close();
      return;
    }
    if (ldapentries.length != 1) {
      out.println("Error: there are multiple certificates with the same UID");
      out.flush();
      out.close();
      return;
    }
    
    X509Certificate  certimpl;
    try {
      certimpl=ldapentries[0].getCertificate();
    }
    catch (Exception exp) {
      out.println("error-----------  "+exp.toString());
      out.flush();
      out.close();
      return;
    }

    String uri = req.getRequestURI();
    String certRevokeUri = uri.substring(0, uri.lastIndexOf('/')) + "/revokecertificate";

    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Certificate details </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2> Certificate Details</H2><BR>");
    out.println("<form name=\"revoke\" action=\"" +
		certRevokeUri + "\" method=\"post\">");
    out.println("<input type=\"hidden\" name=\"distinguishedName\" value=\""
		+ ldapentries[0].getUniqueIdentifier()+"\">");
    if((role==null)||(role=="")) {
      if (debug) {
	System.out.println("got role as null or empty in certificate details:::::++++");
      }
    }
    else {
      out.println("<input type=\"hidden\" name=\"role\" value=\""+role+"\">");
    }
    out.println("<input type=\"hidden\" name=\"cadnname\" value=\""+cadnname+"\">");
    out.println("<b>Version&nbsp;&nbsp;&nbsp;:</b>"
		+certimpl.getVersion());
    out.println("<br>");
    out.println("<b>Subject&nbsp;&nbsp;&nbsp;:</b>"
		+certimpl.getSubjectDN().getName());
    out.println("<br>");
    out.println("<b>Signature Algorithm &nbsp;&nbsp;&nbsp;:</b>"
		+certimpl.getSigAlgName()
		+",<b>&nbsp;OID&nbsp; :</b>"+certimpl.getSigAlgOID());
    out.println("<br>");
    out.println("<b>Key&nbsp;&nbsp;&nbsp;:</b><PRE>"
		+CertificateUtility.toHexinHTML(certimpl.getPublicKey().getEncoded()) + "</PRE>");
    out.println("<br>");
    out.println("<b>Validity&nbsp;&nbsp;&nbsp;:</b>");
    out.println("<br>");
    out.println("<b>&nbsp;&nbsp;&nbsp;From &nbsp;:</b>"
		+certimpl.getNotBefore().toString());
    out.println("<br>");
    out.println("<b>&nbsp;&nbsp;&nbsp;To &nbsp;:</b>"
		+certimpl.getNotAfter().toString());
    out.println("<br>");
    out.println("<b>Issuer&nbsp;&nbsp;&nbsp;:</b>"
		+certimpl.getIssuerDN().getName());
    out.println("<br>");
    out.println("<b>Serial No &nbsp;&nbsp;&nbsp;:</b>"
		+certimpl.getSerialNumber());
    out.println("<br>");
    out.println("<b>Algorithm&nbsp;&nbsp;&nbsp;:</b>"
		+certimpl.getPublicKey().getAlgorithm());
    out.println("<br>");
    out.println("<b>Signature &nbsp;&nbsp;&nbsp;:</b><PRE>"
		+ CertificateUtility.toHexinHTML(certimpl.getSignature())
		+ "</PRE>");
    out.println("<br>");
    out.println("<input type=\"submit\" value=\"Revoke Certificate \">");
    out.println("</form>");
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
