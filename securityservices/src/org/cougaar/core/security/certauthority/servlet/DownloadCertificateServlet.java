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
import java.security.cert.*;
import java.security.MessageDigest;
import sun.security.x509.*;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.crypto.ldap.CertDirectoryServiceFactory;
import org.cougaar.core.security.crypto.ldap.LdapEntry;
import org.cougaar.core.security.certauthority.*;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.crypto.Base64;

public class DownloadCertificateServlet extends  HttpServlet
{
  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;
  private LoggingService log;

  private CertDirectoryServiceClient certificateFinder=null;
  private CaPolicy caPolicy = null;            // the policy of the CA
  
  protected boolean debug = false;

  private SecurityServletSupport support;
  public DownloadCertificateServlet(SecurityServletSupport support) {
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

  public void service (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    
    String distinguishedName=null;
    String role=null;
    String cadnname=null;

    res.setContentType("text/html");
    if (log.isDebugEnabled()) {
      //log.debug("getContextPath:" + req.getContextPath());
      log.debug("getPathInfo:" + req.getPathInfo());
      log.debug("getPathTranslated:" + req.getPathTranslated());
      log.debug("getRequestURI:" + req.getRequestURI());
      log.debug("getServletPath:" + req.getServletPath());
    }

    distinguishedName=req.getParameter("distinguishedName");
    cadnname=req.getParameter("cadnname");
    if (log.isDebugEnabled()) {
      log.debug("CertificateDetailsServlet. Search DN="
			 + distinguishedName
			 + " - cadnname: " + cadnname);
    }
    if((cadnname==null)||(cadnname=="")) {
      res.getWriter().print("Error in dn name ");
      return;
    }
    try {
      configParser = (ConfigParserService)
	support.getServiceBroker().getService(this,
					      ConfigParserService.class,
					      null);
      caPolicy = configParser.getCaPolicy(cadnname);
      certificateFinder = 
	CertDirectoryServiceFactory.getCertDirectoryServiceClientInstance(
				       caPolicy.ldapType, caPolicy.ldapURL,
				       support.getServiceBroker());
    } catch (Exception e) {
      res.getWriter().print("Unable to read policy file: " + e);
      return;
    }
    
    if((distinguishedName==null)||(distinguishedName=="")) {
      res.getWriter().print("Error in distinguishedName ");
      return;
    }
 
    String filter = "(uniqueIdentifier=" +distinguishedName + ")";
    LdapEntry[] ldapentries = certificateFinder.searchWithFilter(filter);
    if(ldapentries==null || ldapentries.length == 0) {
      res.getWriter().println("Error: no such certificate in LDAP ");
      return;
    }
    if (ldapentries.length != 1) {
      res.getWriter().println("Error: there are multiple certificates with the same UID");
      return;
    }
    
    X509Certificate  certimpl;
    byte[] encoded;
    char[] b64;
    try {
      certimpl=ldapentries[0].getCertificate();
      encoded = certimpl.getEncoded();
      b64 = Base64.encode(encoded);
    } catch (Exception exp) {
      res.getWriter().println("error-----------  "+exp.toString());
      return;
    }

    res.reset();
    if (isCA(certimpl.getSubjectDN().getName())) {
      res.setContentType("application/x-x509-ca-cert");
      res.setHeader("Content-Disposition","inline; filename=\"ca.cer\"");
    } else {
      res.setContentType("application/x-x509-user-cert");
      res.setHeader("Content-Disposition","inline; filename=\"user.cer\"");
    } // end of else

    StringBuffer buf = new StringBuffer();
    buf.append("-----BEGIN CERTIFICATE-----\n");
    buf.append(b64);
    buf.append("\n-----END CERTIFICATE-----\n");
    res.setContentLength(buf.length());
    res.getWriter().print(buf.toString());
    res.getWriter().close();
  }

  public static boolean isCA(String dn) {
    StringTokenizer tok = new StringTokenizer(dn,",=",true);
    boolean first = true;
    try {
      while (tok.hasMoreTokens()) {
        if (first) {
          first = false; // first doesn't have a ',' in front
        } else {
          if (!(",".equals(tok.nextToken()))) {
            // bad dn -- expecting ','
            return false;
          } // end of if (!(",".equals(tok.nextToken())))
        } // !first
        String name = tok.nextToken().trim();
        if (!("=".equals(tok.nextToken()))) {
          // bad dn -- expecting '='
          return false;
        } // end of if (!("=".equals(tok.nextToken())))
        String value = tok.nextToken();
        if (name.equalsIgnoreCase("t")) {
          return (value.equalsIgnoreCase("ca"));
        } // end of if (name.equalsIgnoreCase("t"))
      } // end of while (tok.hasMoreTokens())
    } catch (NoSuchElementException e) {
      // invalid dn
    } // end of try-catch
    return false;
  }

  public static boolean isUser(String dn) {
    StringTokenizer tok = new StringTokenizer(dn,",=",true);
    boolean first = true;
    String sep;
    try {
      while (tok.hasMoreTokens()) {
        if (first) {
          first = false; // first doesn't have a ',' in front
        } else {
          sep = tok.nextToken();
          if (!(",".equals(sep))) {
            // bad dn -- expecting ','
            return false;
          } // end of if (!(",".equals(tok.nextToken())))
        } // !first
        String name = tok.nextToken().trim();
        sep = tok.nextToken();
        if (!("=".equals(sep))) {
          //bad dn -- expecting '='
          return false;
        } // end of if (!("=".equals(tok.nextToken())))
        String value = tok.nextToken();
        if (name.equalsIgnoreCase("t")) {
          return (value.equalsIgnoreCase("user"));
        } // end of if (name.equalsIgnoreCase("t"))
      } // end of while (tok.hasMoreTokens())
    } catch (NoSuchElementException e) {
      // invalid dn
    } // end of try-catch
    return false;
  }

  public String getServletInfo()  {
    return("Downloads the certificate to the browser");
  }
  
}
