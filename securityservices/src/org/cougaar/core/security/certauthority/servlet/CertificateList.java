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
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.naming.CertificateEntry;
import org.cougaar.core.security.services.util.CACertDirectoryService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import sun.security.x509.X500Name;

public class CertificateList
  extends HttpServlet
{
  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;

  private X500Name[] caDNs = null;
  //private CaPolicy caPolicy = null;            // the policy of the CA
  //private CertDirectoryServiceClient certificateFinder=null;
  private CACertDirectoryService search;
  private LoggingService log;

  private SecurityServletSupport support;
  public CertificateList(SecurityServletSupport support) {
    this.support = support;
    log = (LoggingService)
      support.getServiceBroker().getService(this,
			       LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
  {
    try {
      secprop = support.getSecurityProperties(this);
      configParser = (ConfigParserService)
	support.getServiceBroker().getService(this,
					      ConfigParserService.class,
					      null);
      search = (CACertDirectoryService)
        support.getServiceBroker().getService(this, CACertDirectoryService.class, null);
      search.refreshBlackboard();
    }
    catch (Exception e) {
      log.error("Unable to initialize servlet:" + e);
    }
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    PrintWriter out=res.getWriter();
    //String domain=null;
    String cadnname=null;

    cadnname =(String)req.getParameter("cadnname");
    if (log.isDebugEnabled()) {
      log.debug(cadnname);
    }
    if((cadnname==null)||( cadnname=="")) {
      out.print("Error ---Unknown  type CA dn name :");
      out.flush();
      out.close();
      return;
    }

    /*
    try {
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
    CertDirServiceRequestor cdsr =
      new CertDirServiceRequestor(support.getServiceBroker(), cadnname);
    */

    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Certificate List</title>");
    out.println("<script language=\"javascript\">");
    out.println("function submitme(form)");
    out.println("{ form.submit()}</script>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Certificate List</H2>");
    out.println("<H3>Issuer: " + cadnname + "</H3>");
    //out.println("<H3>LDAP:   " + caPolicy.ldapURL + "</H3>");

    /*
    String filter = "(cn=*)";
    LdapEntry[] ldapentries = certificateFinder.searchWithFilter(filter);
    out.println("<H3>" + ldapentries.length + " entries</H3>");
    */
    List l = search.getAllCertificates();
    out.println("<H3>" + l.size() + " entries</H3>");

    out.println("<table>");

    String uri = req.getRequestURI();
    String certDetailsUri = uri.substring(0, uri.lastIndexOf('/'))
      + "/CertificateDetailsServlet";

    /*
    if((domain==null)||(domain=="")) {
      domain = null;
    }
    if (log.isDebugEnabled()) {
      log.debug("calling create table will domain:" + domain);
    }
    */
    out.println(createtable(l,
			    cadnname, certDetailsUri));
    out.println("</body></html>");
    out.flush();
    out.close();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
  {
    res.setContentType("text/html");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Certificate List from Ldap </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Certificate List</H2>");

    caDNs = configParser.getCaDNs();
    if (log.isDebugEnabled()) {
      if (caDNs == null || caDNs.length == 0) {
        log.debug("No CA DN");
      }
      else {
        for (int i = 0 ; i < caDNs.length ; i++) {
          log.debug("CA DN: " + caDNs[i].toString());
        }
      }
    }

    if (caDNs == null) {
      out.println("No CA has been configured yet");
    }
    else {
      String uri=req.getRequestURI();
      out.println("<table>");
      out.println("<form action=\"" + uri + "\" method =\"post\">");
      out.println("<tr ><td colspan=\"3\">");
      // Domain
      //out.println("Name space: <select id=\"domain\" name=\"domain\">");
      /*
      if (domains != null) {
	for (int i = 0 ; i < domains.length ; i++) {
	  out.println("<option value=\"" + domains[i] + "\">"
		      + domains[i] + "</option>");
	}
      }
      else {
      }
      */
      out.println("</select>");

      //out.println("Domain <input name=\"domain\" type=\"text\" value=\"\">");

      // Table separators
      out.println(" <br> <br></td></tr>");
      out.println("<tr ><td colspan=\"3\">");

      // CA
      out.println("Select CA: <select id=\"cadnname\" name=\"cadnname\">");

      for (int i = 0 ; i < caDNs.length ; i++) {
	out.println("<option value=\"" + caDNs[i].toString() + "\">"
		    + caDNs[i].toString() + "</option>");
      }
      out.println("</select>");
      //out.println("DN for CA <input name=\"cadnname\" type=\"text\" value=\"\">");

      out.println(" <br> <br></td></tr>");
      out.println("</tr><tr><td></td><td><br><input type=\"submit\">&nbsp;&nbsp;&nbsp;");
      out.println("<input type=\"reset\"></td><td></td></tr>");
      out.println("</form></table>");
    }
    out.println("</body></html>");
    out.flush();
    out.close();
  }

  public String getServletInfo()
  {
    return("List all certificate specified by CAS dn name");
  }

  public String createtable(List l, String cadnname,
			    String certDetailUri)
  {
    StringBuffer sb=new StringBuffer();
    sb.append("<table align=\"center\" border=\"2\">\n");
    sb.append("<TR><TH> DN-Certificate </TH><TH> Status </TH><TH> DN-Signed By </TH></TR>\n");

    //for(int i = 0 ; i < ldapentries.length ; i++) {
    for(int i = 0 ; i < l.size() ; i++) {
      CertificateEntry entry = (CertificateEntry)l.get(i);
      X509Certificate cert = entry.getCertificate();
      sb.append("<TR><TD>\n");
      sb.append("<form name=\"form" + i
		+ "\" action=\"" + certDetailUri + "\" method=\"post\">");
      sb.append("<input type=\"hidden\" name=\"distinguishedName\" value=\""
		//+ ldapentries[i].getUniqueIdentifier()+"\">");
                + CertificateUtility.getUniqueIdentifier(cert)+"\">");
      sb.append("<input type=\"hidden\" name=\"cadnname\" value=\""
		+ cadnname + "\">");
      //sb.append("<input type=\"hidden\" name=\"domain\" value=\"" + domain + "\">");
      sb.append("<a Href=\"javascript:submitme(document.form"
		+ i +")\">"
		+ cert.getSubjectDN().getName()
		+"</a></form></TD>\n");
      sb.append("<TD>"+entry.getCertificateRevocationStatus()+"</TD>\n" );
      sb.append("<TD>"+cert.getIssuerDN().getName()
		+"</TD></TR>\n");
    }
    sb.append("</table>");
    return sb.toString();
  }

}
