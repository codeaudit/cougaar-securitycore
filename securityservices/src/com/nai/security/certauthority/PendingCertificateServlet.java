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

import com.nai.security.crypto.ConfParser;
import com.nai.security.crypto.CertificateUtility;
import com.nai.security.crypto.ldap.CertDirectoryServiceClient;
import com.nai.security.crypto.ldap.CertDirectoryServiceFactory;
import com.nai.security.crypto.ldap.LdapEntry;
import com.nai.security.policy.CaPolicy;

public class PendingCertificateServlet extends  HttpServlet
{
  private ConfParser confParser = null;
  private X500Name[] caDNs = null;
  private String[] roles = null;
  private CaPolicy caPolicy = null;            // the policy of the CA
  private CertDirectoryServiceClient certificateFinder=null;
  protected boolean debug = false;

  public void init(ServletConfig config) throws ServletException
  {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    confParser = new ConfParser();
    caDNs = confParser.getCaDNs();
    roles = confParser.getRoles();
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    PrintWriter out=res.getWriter();
    String role=null;
    String cadnname=null;

    cadnname =(String)req.getParameter("cadnname");
    role =(String)req.getParameter("role");
    if (debug) {
      System.out.println(cadnname + " - " + role);
    }
    if((cadnname==null)||( cadnname=="")) {
      out.print("Error ---Unknown  type CA dn name :");
      out.flush();
      out.close();
      return;
    }

    try {
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

    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Pending Certificate List</title>");
    out.println("<script language=\"javascript\">");
    out.println("function submitme(form)");
    out.println("{ form.submit()}</script>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Pending Certificate List</H2>");
    //out.println("<H3>Issuer: " + cadnname + "</H3>");
    //out.println("<H3>LDAP:   " + caPolicy.ldapURL + "</H3>");

    out.println("<table>");
    String filter = "(cn=*)";

    String uri = req.getRequestURI();
    String certDetailsUri = uri.substring(0, uri.lastIndexOf('/')) + "/pendingdetail";

    if (role == "")
      role = null;
    if (debug) {
      System.out.println("calling create table will role:" + role);
    }

    PendingCertCache pendingCache = PendingCertCache.getPendingCache(cadnname, role);
    Hashtable certtable = (Hashtable)pendingCache.get(caPolicy.pendingDirectory);
    out.println(createtable(certtable,
                            cadnname, role,
                            certDetailsUri));

    out.println("</body></html>");
    out.flush();
    out.close();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
  {
    res.setContentType("Text/HTML");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Certificate Request Pending for Approval </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Pending Certificate Request List</H2>");

    if (caDNs == null) {
      out.println("No CA has been configured yet");
    }
    else {
      out.println("<table>");
      out.println("<form action=\"\" method =\"post\">");
      out.println("<tr ><td colspan=\"3\">");
      // Role
      out.println("Name space: <select id=\"role\" name=\"role\">");
      if (roles != null) {
	for (int i = 0 ; i < roles.length ; i++) {
	  out.println("<option value=\"" + roles[i] + "\">"
		      + roles[i] + "</option>");
	}
      }
      else {
      }
      out.println("</select>");

      //out.println("Role <input name=\"role\" type=\"text\" value=\"\">");

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
    return("List all certificates pending specified by role and CAS dn name");
  }

  public String createtable(Hashtable pendingcerts, String cadnname, String role, String certDetailUri)
  {
    StringBuffer sb=new StringBuffer();
    sb.append("<table align=\"center\" border=\"2\">\n");
    sb.append("<TR><TH> DN-Certificate </TH><TH> Status </TH><TH> DN-Signed By </TH></TR>\n");

    Enumeration en = pendingcerts.keys();
    for(int i = 0 ; en.hasMoreElements() ; i++) {
      String alias = (String)en.nextElement();
      X509Certificate ClientX509 = (X509Certificate)pendingcerts.get(alias);
      sb.append("<TR><TD>\n");
      sb.append("<form name=\"form" + i
		+ "\" action=\"" + certDetailUri + "\" method=\"post\">");
      sb.append("<input type=\"hidden\" name=\"alias\" value=\""
		+ alias +"\">");
      sb.append("<input type=\"hidden\" name=\"cadnname\" value=\""
		+ cadnname + "\">");
      sb.append("<input type=\"hidden\" name=\"role\" value=\"" + role + "\">");
      sb.append("<a Href=\"javascript:submitme(document.form"
		+ i +")\">"
		+ ClientX509.getSubjectDN().getName()
		+"</a></form></TD>\n");
      sb.append("<TD>Pending</TD>\n" );
      sb.append("<TD>"+ClientX509.getIssuerDN().getName()
		+"</TD></TR>\n");
      }
    sb.append("</table>");
    return sb.toString();
  }
}
