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
import javax.security.auth.x500.X500Principal;

// Cougaar security services
import com.nai.security.policy.CaPolicy;
import com.nai.security.crypto.CertificateUtility;
import com.nai.security.crypto.ldap.CertDirectoryServiceClient;
import com.nai.security.crypto.ldap.CertDirectoryServiceFactory;
import com.nai.security.crypto.ldap.LdapEntry;
import com.nai.security.certauthority.*;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.services.identity.*;
import org.cougaar.core.security.services.crypto.*;
import com.nai.security.util.CryptoDebug;

public class CreateCaKeyServlet
  extends  HttpServlet
{
  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;
  private KeyRingService keyRingService= null;

  protected boolean debug = false;

  private SecurityServletSupport support;
  private AgentIdentityService agentIdentity;

  public CreateCaKeyServlet(SecurityServletSupport support) {
    this.support = support;
  }

  public void init(ServletConfig config) throws ServletException
  {
    secprop = support.getSecurityProperties(this);
    debug = (Boolean.valueOf(secprop.getProperty(secprop.CRYPTO_DEBUG,
						"false"))).booleanValue();
    agentIdentity = (AgentIdentityService)
      support.getServiceBroker().getService(this,
					    AgentIdentityService.class,
					    null);
    keyRingService = (KeyRingService)
      support.getServiceBroker().getService(this,
					    KeyRingService.class,
					    null);

  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    String caCN =(String)req.getParameter("CN");
    String caOU =(String)req.getParameter("OU");
    String caO  =(String)req.getParameter("O");
    String caL  =(String)req.getParameter("L");
    String caST =(String)req.getParameter("ST");
    String caC  =(String)req.getParameter("C");

    String caDN = "cn=" + caCN
      + ", ou=" + caOU
      + ", o=" + caO
      + ", l=" + caL
      + ", st=" + caST
      + ", c=" + caC;
    if (CryptoDebug.debug) {
      System.out.println("Creating CA key for: " + caDN);
    }
    PrintWriter out=res.getWriter();
    try {
      X500Name dname = new X500Name(caDN);
    }
    catch (IOException e) {
      out.println("Unable to create CA certificate: " + e);
      e.printStackTrace(out);
      out.flush();
      out.close();
      return;
    }

    X500Principal p = new X500Principal(caDN);
    try {
      agentIdentity.CreateCryptographicIdentity(p, null);
    }
    catch (Exception e) {
      out.println("Unable to generate CA key: " + e);
      e.printStackTrace(out);
      out.flush();
      out.close();
      return;
    }

    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>CA key generation</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>CA key generation</H2>");
    out.println("CA key has been generated<br>");
    out.println("CA private key has been stored in " + keyRingService.getKeyStorePath());
    out.println("<br>CA certificate has been stored in " + keyRingService.getCaKeyStorePath());
    out.println("<br></body></html>");
    out.flush();
    out.close();
  }
  
  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    res.setContentType("Text/HTML");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>CA key generation</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>CA key generation</H2>");
    out.println("<table>");
    out.println("<form action=\"\" method =\"post\">");

    out.println("<tr ><td colspan=\"3\">");
    out.println("CN: <input name=\"CN\" type=\"text\" value=\"\">");
    out.println(" <br> <br></td></tr>");

    out.println("<tr ><td colspan=\"3\">");
    out.println("OU: <input name=\"OU\" type=\"text\" value=\"\">");
    out.println(" <br> <br></td></tr>");

    out.println("<tr ><td colspan=\"3\">");
    out.println("O: <input name=\"O\" type=\"text\" value=\"\">");
    out.println(" <br> <br></td></tr>");

    out.println("<tr ><td colspan=\"3\">");
    out.println("L: <input name=\"L\" type=\"text\" value=\"\">");
    out.println(" <br> <br></td></tr>");

    out.println("<tr ><td colspan=\"3\">");
    out.println("ST: <input name=\"ST\" type=\"text\" value=\"\">");
    out.println(" <br> <br></td></tr>");

    out.println("<tr ><td colspan=\"3\">");
    out.println("C: <input name=\"C\" type=\"text\" value=\"\">");
    out.println(" <br> <br></td></tr>");

    out.println("</td></tr>");

    out.println("</tr><tr><td></td><td><br><input type=\"submit\">&nbsp;&nbsp;&nbsp;");
    out.println("<input type=\"reset\"></td><td></td></tr>");
    out.println("</form></table>");
    out.println("</body></html>");
    out.flush();
    out.close();
    
  }
  
  public String getServletInfo()  {
    return("Generate a CA key");
  }
  
}
