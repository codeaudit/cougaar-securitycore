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

// Cougaar security services
import com.nai.security.crypto.*;
import com.nai.security.crypto.ldap.CertDirectoryServiceCA;
import com.nai.security.crypto.ldap.CertDirectoryServiceClient;
import com.nai.security.crypto.ldap.CertDirectoryServiceFactory;
import com.nai.security.crypto.ldap.LdapEntry;
import com.nai.security.policy.CaPolicy;
import org.cougaar.core.security.services.util.*;
import com.nai.security.certauthority.*;

public class ProcessPendingCertServlet extends  HttpServlet
{
  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;
  private CaPolicy caPolicy = null;            // the policy of the CA
  private NodeConfiguration nodeConfiguration;
  private CertDirectoryServiceCA caOperations=null;
  protected boolean debug = false;
  private SecurityServletSupport support;

  public ProcessPendingCertServlet(SecurityServletSupport support) {
    this.support = support;
  }

  public void init(ServletConfig config) throws ServletException
  {
    secprop = support.getSecurityProperties(this);

    debug = (Boolean.valueOf(secprop.getProperty(secprop.CRYPTO_DEBUG,
						"false"))).booleanValue();
    configParser = (ConfigParserService)
      support.getServiceBroker().getService(this,
					    ConfigParserService.class,
					    null);
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    PrintWriter out=res.getWriter();
    res.setContentType("Text/HTML");
    String alias=req.getParameter("alias");
    //String role=req.getParameter("role");
    String cadnname=req.getParameter("cadnname");
    out.println("<html>");
    out.println("<script language=\"javascript\">");
    out.println("function submitme(form)");
    out.println("{ form.submit()}</script>");
    out.println("</head>");

    out.println("<body>");

    if((alias==null)||(alias=="")) {
      out.println("Error in getting the certificate alias");
      out.flush();
      out.close();
      return;
    }
    if((cadnname==null)||(cadnname=="")) {
      out.println("Error in getting the CA's DN ");
      out.flush();
      out.close();
      return;
    }

    try {
      caPolicy = configParser.getCaPolicy(cadnname);
      nodeConfiguration = new NodeConfiguration(cadnname);
      caOperations =
	CertDirectoryServiceFactory.getCertDirectoryServiceCAInstance(
				       caPolicy.ldapType, caPolicy.ldapURL);
    }
    catch (Exception e) {
      out.print("Unable to read policy file: " + e);
      out.flush();
      out.close();
      return;
    }

    String actionType = req.getParameter("actiontype");
    // 0 is deny, 1 is approve, -1 is unknown status
    if (actionType != null) {
      // retrieve pending certificate
      X509Certificate  certimpl;
      try {
        //certimpl=ldapentries[0].getCertificate();
        PendingCertCache pendingCache =
	  PendingCertCache.getPendingCache(cadnname, support.getServiceBroker());
        certimpl = (X509Certificate)
          pendingCache.getCertificate(nodeConfiguration.getPendingDirectoryName(cadnname),
				      alias);

        if (actionType.indexOf("Approve") >= 0) {
          caOperations.publishCertificate(certimpl,CertificateUtility.EntityCert,null);
          out.println("Certificate is now approved: " +
            certimpl.getSubjectDN().getName());
          // need to move to approved directory
          pendingCache.moveCertificate(
            nodeConfiguration.getPendingDirectoryName(cadnname),
	    nodeConfiguration.getX509DirectoryName(cadnname),
	    alias);
        }
        if (actionType.indexOf("Deny") >= 0) {
          out.println("Certificate is denied: " +
            certimpl.getSubjectDN().getName());
          // need to move to denied directory
          pendingCache.moveCertificate(
	    nodeConfiguration.getPendingDirectoryName(cadnname),
	    nodeConfiguration.getDeniedDirectoryName(cadnname), alias);
        }
      }
      catch (Exception exp) {
        out.println("error-----------  "+exp.toString());
        out.flush();
        out.close();
        return;
      }

    }
    String uri = req.getRequestURI();
    String certlistUri = uri.substring(0, uri.lastIndexOf('/')) + "/PendingCertificateServlet";
    out.println(appendForm(certlistUri,cadnname));

    out.println("</body>");
    out.println("</html>");

  }
  private String appendForm(String posturl, String caDNName) {
    
    StringBuffer sb=new StringBuffer();
     sb.append("<form name=\"certlist\" action=\"" +posturl
	       + "\" method=\"post\">");
     sb.append("<input type=\"hidden\" name=\"cadnname\" value=\""
		+caDNName + "\">");
     //sb.append("<input type=\"hidden\" name=\"role\" value=\""
     //       + role + "\">");
     sb.append("<a Href=\"javascript:submitme(document.certlist)\">"
		+ "Back to List "+"</a></form>");
     return sb.toString();
  }

  protected void doGet(HttpServletRequest req,
		       HttpServletResponse res)
    throws ServletException, IOException
  {
  }

  public String getServletInfo()
  {
    return("Process the order to either deny or approve a pending certificate.");
  }


}

