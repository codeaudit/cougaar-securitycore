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
//import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.naming.*;
import org.cougaar.core.security.certauthority.*;
import org.cougaar.core.security.services.util.*;
/*
import org.cougaar.core.security.services.ldap.MultipleEntryException;
import org.cougaar.core.security.services.ldap.LdapEntry;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;
*/
import org.cougaar.core.security.crypto.Base64;

public class DownloadCertificateServlet extends  HttpServlet
{
  //private ConfigParserService configParser = null;
  private LoggingService log;

  //private CertDirectoryServiceClient certificateFinder=null;
  private CACertDirectoryService search;
  //private CaPolicy caPolicy = null;            // the policy of the CA

  private SecurityServletSupport support;
  public DownloadCertificateServlet(SecurityServletSupport support) {
    this.support = support;
    log = (LoggingService)
      support.getServiceBroker().getService(this,
			       LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
  {
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

    } catch (Exception e) {
      res.getWriter().print("Unable to read policy file: " + e);
      return;
    }
    */
    CertDirServiceRequestor cdsr =
      new CertDirServiceRequestor(support.getServiceBroker(), cadnname);
    search = (CACertDirectoryService)
      support.getServiceBroker().getService(cdsr, CACertDirectoryService.class, null);

    if((distinguishedName==null)||(distinguishedName=="")) {
      res.getWriter().print("Error in distinguishedName ");
      return;
    }

    /*
    String filter = "(uniqueIdentifier=" +distinguishedName + ")";
    LdapEntry[] ldapentries = certificateFinder.searchWithFilter(filter);
    if(ldapentries==null || ldapentries.length == 0) {
    */
    CertificateEntry ce = search.findCertByIdentifier(distinguishedName);
    if (ce == null) {
      res.getWriter().println("Error: no such certificate found");
      return;
    }

    X509Certificate  certimpl = ce.getCertificate();
    byte[] encoded;
    char[] b64;
    try {
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
    return CertificateUtility.findAttribute(dn, "t").equals(CertificateCache.CERT_TITLE_CA);
  /*
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
    */
  }

  public static boolean isUser(String dn) {
    return CertificateUtility.findAttribute(dn, "t").equals(CertificateCache.CERT_TITLE_USER);
  /*
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
    */
  }

  public String getServletInfo()  {
    return("Downloads the certificate to the browser");
  }

}
