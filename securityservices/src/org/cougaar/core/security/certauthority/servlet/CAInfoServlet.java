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
import java.security.cert.*;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.certauthority.*;
import org.cougaar.core.security.util.NodeInfo;

public class CAInfoServlet
  extends HttpServlet {

  private ConfigParserService configParser = null;
  private LoggingService log;
  private SecurityServletSupport support;

  private CAInfo _info = null;
  private String httpsport = null;

  public CAInfoServlet(SecurityServletSupport support) {
    this.support = support;
    log = (LoggingService)
      support.getServiceBroker().getService(this,
			       LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
  {
    configParser = (ConfigParserService)
      support.getServiceBroker().getService(this,
					    ConfigParserService.class,
					    null);
    httpsport = System.getProperty("org.cougaar.lib.web.https.port", null);
  }

  private CAInfo getCAInfo() {
    if (log.isDebugEnabled()) {
      log.debug("getCAInfo.");
    }

    X500Name [] caDNs = configParser.getCaDNs();
    if (caDNs == null || caDNs.length == 0)
      return null;
    X500Name caDN = caDNs[0];
    KeyRingService krs = (KeyRingService)
      support.getServiceBroker().getService(this,
					    KeyRingService.class,
					    null);
    List l = krs.findCert(caDN, KeyRingService.LOOKUP_KEYSTORE, true);
    if (l == null || l.size() == 0) {
      if (log.isWarnEnabled()) {
        log.warn("Cannot find CA certificate " + caDN + " but CA key has already generated.");
      }
      return null;
    }
    CertificateStatus cs = (CertificateStatus)l.get(0);
    X509Certificate [] certChain = null;
    try {
      certChain = krs.checkCertificateTrust((X509Certificate)cs.getCertificate());
    } catch (CertificateException cex) {
      if (log.isWarnEnabled()) {
        log.warn("CA certificate not trusted!", cex);
        return null;
      }
    }

    // cert request will use https, so need to wait til server cert has
    // been approved
    if (!(httpsport == null || httpsport.equals("-1"))) {
      l = krs.findCert(NodeInfo.getHostName(), KeyRingService.LOOKUP_KEYSTORE, true);
      if (l == null || l.size() == 0) {
        if (log.isWarnEnabled()) {
          log.warn("Host cert has not been signed by CA yet.");
        }
        return null;
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("replying with CA info.");
    }

    SecurityPolicy[] sp =
      configParser.getSecurityPolicies(CryptoClientPolicy.class);
    CryptoClientPolicy ccp = (CryptoClientPolicy) sp[0];
    TrustedCaPolicy tc = new TrustedCaPolicy();
    tc.caDN = caDN.toString();

    CaPolicy caPolicy = configParser.getCaPolicy(tc.caDN);
    tc.caURL = "";
    tc.certDirectoryUrl = caPolicy.ldapURL;
    tc.certDirectoryPrincipal = caPolicy.ldapPrincipal;
    tc.certDirectoryCredential = caPolicy.ldapCredential;
    tc.certDirectoryType = caPolicy.ldapType;
    tc.setCertificateAttributesPolicy(ccp.getCertificateAttributesPolicy());

    CAInfo info = new CAInfo();
    info.caCert = certChain;
    info.caPolicy = tc;

    return info;
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    try {
      synchronized (this) {
        if (_info == null) {
          _info = getCAInfo();

          if (_info == null) {
            return;
          }
        }
      }

      res.setContentType("text/html");

      ObjectOutputStream oos = new ObjectOutputStream(res.getOutputStream());
      oos.writeObject(_info);
    }
    catch (Exception e) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to response ", e);
      }
    }

  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
  {
  }

  public String getServletInfo()
  {
    return("For unzip & run only, returns CA certificate attribute policy and CA certificate.");
  }

}
