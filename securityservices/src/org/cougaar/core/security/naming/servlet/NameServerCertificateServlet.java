/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
 


package org.cougaar.core.security.naming.servlet;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;

import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.service.LoggingService;

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
    String errString = null;
    try {
      if (log.isDebugEnabled()) {
        log.debug("doPost");
      }

      res.setContentType("text/html");

      // if a request comes in for naming certificate,
      // reply if found, if not ask upper CA
      ObjectInputStream ois = new ObjectInputStream(req.getInputStream());

      Object obj = ois.readObject();
      ois.close();

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
          NameServerCertificate nameCert = (NameServerCertificate)
            NameServerCertificateComponent.getNameServerCert(names[i]);
          if (nameCert == null) {
            if (log.isDebugEnabled()) {
              log.debug("Did not find a cert for " + names[i]);
            }
            //_pendingCache.add(names[i]);
                        
            NameServerCertificateComponent.getPendingList().put(names[i], names[i]);
          }
	  else {
	    if (log.isDebugEnabled()) {
	      log.debug("Found a cert for " + names[i]);
	    }
	  }
          certs[i] = nameCert;
        }

        ObjectOutputStream oos = new ObjectOutputStream(res.getOutputStream());
        oos.writeObject(certs);
        oos.flush();
        oos.close(); 
        return;
      }
      else if (obj instanceof NameServerCertificate) {

        NameServerCertificate nc = (NameServerCertificate)obj;
        if (log.isDebugEnabled()) {
	  log.debug("received name server cert from " + nc);
        }
        //_certCache.put(nc.nameserver, nc.cert);
        NameServerCertificateComponent.addToNameCertCache(nc);
        CertificateCacheService cacheservice = (CertificateCacheService)
            AccessController.doPrivileged(new PrivilegedAction() {
                public Object run() {
                  return 
                    support.getServiceBroker().
                    getService(this,
                               CertificateCacheService.class, null);
                }
              });
        for (int i = 0; i < nc.getCertChain().length; i++) {
          cacheservice.addSSLCertificateToCache(nc.getCertChain()[i]);
        }
        support.getServiceBroker().releaseService(this,
          CertificateCacheService.class, cacheservice);
      }
      else {
        errString = "received unknown request: ";
	if (obj != null) {
	  errString = errString + obj.getClass().getName();
	}
      }
    }
    catch (Exception e) {
      errString = "Unable to respond: " + e.toString();
      if (log.isWarnEnabled()) {
	log.warn(errString, e);
      }
    }
    if (errString != null) {
      if (log.isWarnEnabled()) {
        log.warn(errString);
      }
    } else {
      errString = "request successful";
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
