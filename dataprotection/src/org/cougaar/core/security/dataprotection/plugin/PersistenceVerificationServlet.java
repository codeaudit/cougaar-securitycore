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


package org.cougaar.core.security.dataprotection.plugin;

import org.cougaar.core.security.util.SecurityServletSupport;
import org.cougaar.core.security.dataprotection.DataProtectionStatus;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PersistenceVerificationServlet
  extends  HttpServlet
{
  public PersistenceVerificationServlet(SecurityServletSupport support) {
  }

  public void init(ServletConfig config)
    throws ServletException
  {
  }

  public void doPost (HttpServletRequest req, HttpServletResponse res)
    throws ServletException,IOException
  {
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    String type = req.getParameter("type");
    if (type == null) {
      type = "BOTH";
    }

    res.setContentType("text/html");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Persistence Status </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Persistence Status </H2>");

    StringBuffer sb=new StringBuffer();

    if (!type.equals("INPUT")) {
      Hashtable h = DataProtectionStatus.getOutputStatus();
      sb.append("Output status:<br>\n");
      writeStatus(h, sb);
    }
    if (!type.equals("OUTPUT")) {
      sb.append("Input status:<br>\n");
      Hashtable h = DataProtectionStatus.getInputStatus();
      writeStatus(h, sb);
    }

    out.println(sb.toString());

    out.println("</body></html>");
    out.flush();
    out.close();
  }

  private void writeStatus(Hashtable h, StringBuffer sb) {
    sb.append("<table align=\"center\" border=\"2\">\n");
    sb.append("<TR><TH> Timestamp </TH><TH> Agent </TH><TH> Status </TH></TR>\n");
    for (Enumeration en = h.elements(); en.hasMoreElements(); ) {
      List statusList = (List)en.nextElement();
      for (int i = 0; i < statusList.size(); i++) {
        DataProtectionStatus status = (DataProtectionStatus)
          statusList.get(i);
        sb.append("<TR><TD>"+status.timestamp+"</TD>" );
        sb.append("<TD>"+status.agent+"</TD>" );
        sb.append("<TD>"+status.status+"</TD></TR>");
      }
    }
    sb.append("</table>");
  }

  public String getServletInfo()  {
    return("For test case verification, displays persistence times and status.");
  }

}
