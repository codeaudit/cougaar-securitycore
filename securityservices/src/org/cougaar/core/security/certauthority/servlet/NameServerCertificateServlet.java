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
import sun.security.x509.*;

import org.cougaar.core.service.*;

import org.cougaar.core.security.certauthority.SecurityServletSupport;
import org.cougaar.core.security.naming.servlet.*;
import org.cougaar.core.security.services.crypto.*;

public class NameServerCertificateServlet extends HttpServlet {
  private SecurityServletSupport support;
  private LoggingService log;

  public NameServerCertificateServlet(SecurityServletSupport support) {
    this.support = support;
  }

  public void init(ServletConfig config)
    throws ServletException
  {
    log = (LoggingService)
      support.getServiceBroker().getService(this,
					    LoggingService.class,
					    null);
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    String errString = "request successful";
    try {
      if (log.isDebugEnabled()) {
        log.debug("doPost");
      }

      res.setContentType("text/html");

      // if a request comes in for naming certificate,
      // reply if found, if not ask upper CA
      ObjectInputStream ois = new ObjectInputStream(req.getInputStream());

      Object obj = ois.readObject();
      // this is a query
      if (obj instanceof String []) {

        String [] names = (String [])obj;

        if (log.isDebugEnabled()) {
	  log.debug("received request for name server cert, size " + names.length);
        }

        NameServerCertificate [] certs = new NameServerCertificate[names.length];
        for (int i = 0; i < names.length; i++) {
          if (log.isDebugEnabled()) {
            log.debug("checking whether we have " + names[i]);
          }
          X509Certificate [] cert = (X509Certificate [])/*_certCache.get(names[i]);*/
            NameServerCertificateComponent.getNameServerCert(names[i]);
          if (cert == null) {
            //_pendingCache.add(names[i]);
            NameServerCertificateComponent.getPendingList().add(names[i]);
          }
          certs[i] = new NameServerCertificate(names[i], cert);
        }

        ObjectOutputStream oos = new ObjectOutputStream(res.getOutputStream());
        oos.writeObject(certs);
        return;
      }
      else if (obj instanceof NameServerCertificate) {

        NameServerCertificate nc = (NameServerCertificate)obj;
        if (log.isDebugEnabled()) {
	  log.debug("received name server cert from " + nc);
        }
        //_certCache.put(nc.nameserver, nc.cert);
        NameServerCertificateComponent.addToNameCertCache(nc.nameserver, nc.certChain);
        CertificateCacheService cacheservice = (CertificateCacheService)
          support.getServiceBroker().getService(this,
                             CertificateCacheService.class, null);
        for (int i = 0; i < nc.certChain.length; i++) {
          cacheservice.addSSLCertificateToCache(nc.certChain[i]);
        }
        support.getServiceBroker().releaseService(this,
          CertificateCacheService.class, cacheservice);
      }
      else {
        errString = "received unknown request";
      }
    }
    catch (Exception e) {
      errString = "Unable to response " + e.toString();
    }
    PrintWriter out = res.getWriter();
    out.println(errString);
    out.flush();
    out.close();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
  {
  }

  public String getServletInfo()
  {
    return("For unzip & run only, returns name server certificate.");
  }

}
