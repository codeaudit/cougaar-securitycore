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


package org.cougaar.core.security.crypto.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.service.LoggingService;

public class MakeCertificateServlet
  extends  HttpServlet
{
  private SecurityServletSupport _support;
  private KeyRingService _keyRing;
  private CertificateCacheService _cacheservice;
  private LoggingService _log;

  public MakeCertificateServlet(SecurityServletSupport support) {
    _support = support;
    _log = (LoggingService)
      _support.getServiceBroker().getService(this,
					    LoggingService.class, null);
    _keyRing = (KeyRingService)
      _support.getServiceBroker().getService(this,
					    KeyRingService.class, null);
    _cacheservice = (CertificateCacheService)
      _support.getServiceBroker().getService(this,
					    CertificateCacheService.class, null);
  }

  public void init(ServletConfig config)
    throws ServletException
  {
  }

  public void doPost (HttpServletRequest req, HttpServletResponse res)
    throws ServletException,IOException
  {
    String cname = req.getParameter("identifier");
    
    String msg = "Successfully requested new certificate for " + cname;
    if (cname != null) {
      try {
        _keyRing.addToIgnoredList(cname);
        // remove the entries first

        _cacheservice.removeEntryFromCache(cname);
        _keyRing.removeEntry(cname);
 
        // now force to get new certificates for this identifier
        _keyRing.checkOrMakeCert(cname);   
      } catch (Exception ex) {
        // should throw an IDMEF message
        if (ex instanceof GeneralSecurityException) {
          return;
        }
        msg = ex.toString();
      }          
    }
    else {
      msg = "no identifier provided, no action.";
    }

    res.setContentType("text/html");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Make new certificates </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Make new certificates </H2>");

    out.println(msg);

    out.println("</body></html>");
    out.flush();
    out.close();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
  }

  public String getServletInfo()  {
    return("For certificate expiry test cases, remove valid certificates and go request a expired one.");
  }

}
