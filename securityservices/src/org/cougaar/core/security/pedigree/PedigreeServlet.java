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

package org.cougaar.core.security.pedigree;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.services.auth.PedigreeService;
import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.service.LoggingService;


/**
 * @author srosset
 *
 * A servlet that displays statistics about pedigree of blackboard objects
 */
public class PedigreeServlet
extends  HttpServlet
{
  private SecurityServletSupport        _support;
  private PedigreeManagerService        _pedigreeService;
  private LoggingService                _log;
  
  public PedigreeServlet(SecurityServletSupport support) {
    _support = support;
    _log = (LoggingService)
    _support.getServiceBroker().getService(this,
        LoggingService.class, null);
    _pedigreeService = (PedigreeManagerService)
    _support.getServiceBroker().getService(this, PedigreeManagerService.class, null);
  }
  
  public void doPost (HttpServletRequest req, HttpServletResponse res)
  throws ServletException,IOException {
  }
  
  protected void doGet(HttpServletRequest req,HttpServletResponse res)
  throws ServletException, IOException  {
    res.setContentType("text/html");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Make new certificates </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Make new certificates </H2>");

    outputPedigreeStatistics(out);
    
    out.println("</body></html>");
    out.flush();
    out.close();
  }
  
  /**
   * @param out - the output of the servlet.
   */
  private void outputPedigreeStatistics(PrintWriter out) {
  }

  public String getServletInfo()  {
    return("Pedigree data statistics");
  }
}