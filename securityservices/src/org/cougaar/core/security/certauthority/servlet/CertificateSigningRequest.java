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
import sun.security.x509.*;

import org.w3c.dom.*;

// Cougaar core infrastructure
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.util.*;

// Cougaar security services
import org.cougaar.core.security.services.util.*;
import  org.cougaar.core.security.services.crypto.CertificateManagementService;
import  org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.certauthority.*;
import org.cougaar.core.security.crypto.CertificateUtility;

public class CertificateSigningRequest
  extends  HttpServlet
{
  private CertificateManagementService signer;
  private SecurityServletSupport support;
  private LoggingService log;

  public CertificateSigningRequest(SecurityServletSupport support) {
    if (support == null) {
      throw new IllegalArgumentException("Support services null");
    }
    this.support = support;
    log = (LoggingService)
	support.getServiceBroker().getService(this,
	LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
  {
    super.init(config);
  }

  public void doPost (HttpServletRequest req, HttpServletResponse res)
    throws ServletException,IOException
  {
    String pkcs=null;
    String type=null;
    String CA_DN_name=null;
    //String domain = null;

    String data;

    if (log.isDebugEnabled()) {
      log.debug("Received a certificate signing request");
    }
    ByteArrayInputStream bytestream=null;
    PrintStream printstream=new PrintStream(res.getOutputStream());

    //res.setContentType("text/html");
    //  PrintWriter out=res.getWriter();
    CA_DN_name =(String)req.getParameter("dnname");

    try {
      //domain = CertificateUtility.getX500Domain(CA_DN_name, true, ',', true);
      byte [] bytedata=null;

      if(( CA_DN_name==null)||( CA_DN_name=="")) {
	printstream.print("Error ---Unknown  type CA dn name :");
	printstream.flush();
	printstream.close();
	return;
      }
      try  {
	/*
	String aDomain = null;
	if( (domain != null) && (domain != ""))  {
	  aDomain = domain;
	}
	*/
	signer =
	  (CertificateManagementService)support.getServiceBroker().getService(
	    new CertificateManagementServiceClientImpl(CA_DN_name),
	    CertificateManagementService.class, null);
      }
      catch (Exception exp)  {
	printstream.print("Error ---" + exp.toString());
	printstream.flush();
	printstream.close();
	return;
      }

      type=req.getParameter("pkcs");
      if((type==null)||(type==""))  {
	printstream.print("Error --- Unknown pkcs type:");
	printstream.flush();
	printstream.close();
	return;
      }
      pkcs=(String)req.getParameter("pkcsdata");

      String replyformat = (String)req.getParameter("replyformat");
      if (replyformat == null)
        replyformat = "text";

      boolean replyhtml = replyformat.equalsIgnoreCase("html");
      if (replyhtml)
        printstream.println("<html>");
      log.debug("Replying with " + replyformat);

      try  {
	if(type.equalsIgnoreCase("pkcs7"))  {
	  bytedata=pkcs.getBytes();
	  bytestream=new ByteArrayInputStream(bytedata);
	  signer.processX509Request(printstream,(InputStream)bytestream);

	}
	else if(type.equalsIgnoreCase("pkcs10"))  {
	  bytedata=pkcs.getBytes();
	  bytestream=new ByteArrayInputStream(bytedata);

          if (replyhtml) {
            String reply = signer.processPkcs10Request(
              (InputStream)bytestream, true);

            log.debug("reply: " + reply);

            // is it pending? then display pending msg
            String strStat = "status=";
            int statindex = reply.indexOf(strStat);
            if (statindex >= 0) {
              // in the pending mode
              statindex += strStat.length();
              int status = Integer.parseInt(reply.substring(statindex,
                                                            statindex + 1));
              switch (status) {
	      case KeyManagement.PENDING_STATUS_PENDING:
		printstream.println("Certificate is pending for approval.");
		break;
	      case KeyManagement.PENDING_STATUS_DENIED:
		printstream.println("Certificate is denied by CA.");
		break;
	      default:
		printstream.println("Unknown certificate status:" + status);
              }
            }
            else {
              printstream.print(reply);
            }
          }
          else {
            String reply = signer.processPkcs10Request(
	      (InputStream)bytestream, false);
	    printstream.print(reply);
	  }
	}
	else  {
	  printstream.print("Error ----Got a wrong parameter for type"+type);
	}
        if (replyhtml)
          printstream.println("</html>");
      }
      catch (Exception  exp)  {
	printstream.print("Error ------"+exp.toString());
	printstream.flush();
	printstream.close();

      }
      finally  {
	printstream.flush();
	printstream.close();
      }
    }
    catch (Exception e1) {
      printstream.print("Error ------"+e1.toString());
      printstream.flush();
      printstream.close();
    }
  }

  protected void doGet(HttpServletRequest req,
		       HttpServletResponse res)
    throws ServletException, IOException  {
    if (log.isDebugEnabled()) {
      log.debug("+++++ Certificate signing request: ");
      log.debug("method:" + req.getMethod());
      log.debug("authType:" + req.getAuthType());
      log.debug("pathInfo:" + req.getPathInfo());
      log.debug("query:" + req.getQueryString());
    }

    res.setContentType("Text/HTML");
    PrintWriter out=res.getWriter();

    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Certificate Signing request </title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2> Certificate Signing Request</H2>");
    out.println("<table>");
    out.println("<form action=\"\" method =\"post\">");
    //out.println("<tr ><td colspan=\"3\">");
    //out.println("Domain : <input name=\"domain\" type=\"text\" value=\"\">");
    //out.println(" <br> <br></td></tr>");
    out.println("<tr ><td colspan=\"3\">");
    out.println("DN for CA <input name=\"dnname\" type=\"text\" value=\"\">");
    out.println(" <br> <br></td></tr>");
    out.println("<tr ><td colspan=\"3\">");
    out.println("<textarea name=\"pkcsdata\" rows=10 cols=80 ></textarea><br>");
    out.println("</td></tr>");
    out.println("<tr><td>Type :</td>");
    out.println("<td>");
    out.println("<input name=\"pkcs\" type=\"radio\" value=\"pkcs7\">pkcs7</input>&nbsp;&nbsp;&nbsp;");
    out.println("<input name=\"pkcs\" type=\"radio\" value=\"pkcs10\">pkcs10</input>");
    // to distinguish between input from browser and from program
    out.println("<input name=\"replyformat\" type=\"hidden\" value=\"html\"></input>");
    out.println("<br></td><td></td>");
    out.println("</tr><tr><td></td><td><br><input type=\"submit\">&nbsp;&nbsp;&nbsp;");
    out.println("<input type=\"reset\"></td><td></td></tr>");
    out.println("</form></table>");
    out.println("</body></html>");
    out.flush();
    out.close();
  }

  public String getServletInfo()
  {
    return("Accepts signing request and returns signed certificate");
  }

  private class CertificateManagementServiceClientImpl
    implements CertificateManagementServiceClient
  {
    private String caDN;
    public CertificateManagementServiceClientImpl(String aCaDN) {
      caDN = aCaDN;
    }
    public String getCaDN() {
      return caDN;
    }
  }
}
