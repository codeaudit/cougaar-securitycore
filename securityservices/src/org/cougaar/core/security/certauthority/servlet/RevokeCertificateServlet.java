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

import java.security.PrivateKey;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.ldap.LdapEntry;
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.services.ldap.MultipleEntryException;
//import org.cougaar.core.security.services.ldap.LdapEntry;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceCA;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.certauthority.*;

public class RevokeCertificateServlet
extends HttpServlet
{
  public static String HEADER_WITH_SCRIPT = "<html>" +
  "<script language=\"javascript\">" +
  "function submitme(form)" +
  "{ form.submit()}</script>" +
  "</head>" +
  "<body>";
  private SecurityPropertiesService secprop = null;
  private CertificateManagementService keymanagement=null;
  
  javax.servlet.ServletContext context=null;
  protected boolean debug = false;
  private LoggingService log;

  private SecurityServletSupport support;
  public RevokeCertificateServlet(SecurityServletSupport support) {
    this.support = support;

    this.log = (LoggingService)
      support.getServiceBroker().getService(this,
                                            LoggingService.class, null);

  }

  public void init(ServletConfig config) throws ServletException
    {
      context=config.getServletContext();

      secprop = support.getSecurityProperties(this);
     
      debug = (Boolean.valueOf(secprop.getProperty(secprop.CRYPTO_DEBUG,
                                                   "false"))).booleanValue();
      if(debug)
        log.debug(" context is :"+ context.toString());
    }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
    {
      String revokeType = req.getParameter("revoke_type");
    
      if(revokeType != null && revokeType.equals("agent")) {
        revokeAgentCertificate(req, res); 
      }
      else {
        revokeCertificate(req, res);
      }
    }
  
  private void revokeCertificate(HttpServletRequest  req, HttpServletResponse res) 
    throws ServletException,IOException 
    {
      String distinguishedName=null;
      String domain=null;
      String cadnname=null;
      boolean error = false;
      PrintWriter out = res.getWriter();
      res.setContentType("text/html");   
      out.println(getHeaderWithScript());
   
      distinguishedName=req.getParameter("distinguishedName");
      domain=req.getParameter("domain");
      cadnname=req.getParameter("cadnname");
      
      if((distinguishedName==null)||(distinguishedName=="")) {
        out.println("Error in getting the certificate unique identifier");
        error = true;
      }
      if((cadnname==null)||(cadnname=="")) {
        out.println("Error in getting the CA's DN ");
        error = true;
      }

      if(error) {
        out.println(getFooter());
        out.flush();
        out.close();
        return; 
      }
    
      int status = 0;
      String uri = req.getRequestURI();
      String certlistUri = uri.substring(0, uri.lastIndexOf('/')) + "/CertificateList";
      try {
        keymanagement =
          (CertificateManagementService)support.getServiceBroker().getService(
            new CertificateManagementServiceClientImpl(cadnname),
            CertificateManagementService.class, null);
        String uniqueIdentifier=distinguishedName;
        status=keymanagement.revokeCertificate(cadnname,uniqueIdentifier);
      }
      catch (MultipleEntryException multipleexp) {
        out.print("Multiple entry found for : " + multipleexp.getMessage());
        out.println(appendForm(certlistUri,cadnname,domain));
        out.println(getFooter());
        out.flush();
        out.close();
        return;
      }
      catch (Exception generalexp) {
        out.print("Error has occured due to  following reason  : "
                  + generalexp.getMessage());
        out.println(appendForm(certlistUri,cadnname,domain));
        out.println(getFooter()); 
        out.flush();
        out.close();
        return;
      }
    
      out.println(getStatusMsg(status, distinguishedName));
      out.println("<p>");
      out.println(appendForm(certlistUri,cadnname,domain));
      out.println(getFooter()); 
    }
  
  private void revokeAgentCertificate(HttpServletRequest  req, HttpServletResponse res) 
    throws ServletException,IOException 
    {
      //PrintWriter out = res.getWriter();
      PrintStream out = new PrintStream(res.getOutputStream());
      String agentName = req.getParameter("agent_name");
      String caDN = req.getParameter("ca_dn");
      String replyFormat = req.getParameter("reply_format");
      boolean replyHtml = false;
      if(replyFormat != null && replyFormat.equalsIgnoreCase("html")) {
        replyHtml = true;
      }
      boolean error = false;
      if(replyHtml) {
        out.println(getHeader());
      }
      if(agentName == null || agentName == "") {
        out.println("Error getting name of agent");
        error = true;
      }
      if(caDN == null || caDN == "") {
        out.println("Error getting the certificate distinguished name");
        error = true;
      }
    
      if(error) {
        if(replyHtml) {
          out.println(getFooter());
        }
        out.flush();
        out.close();
        return; 
      }
    
      int status = 0;
      try  {
        keymanagement =
          (CertificateManagementService)support.getServiceBroker().getService(
            new CertificateManagementServiceClientImpl(caDN),
            CertificateManagementService.class, null);
        status = keymanagement.revokeAgentCertificate(caDN, agentName);
      }
      catch (MultipleEntryException mee) {
        out.println("Multiple entry found for : " + mee.getMessage());
        error = true;
      }
      catch (Exception e) {
        out.println("Error has occured due to  following reason  : "
                    + e.getMessage());
        error = true;
      }
	  
      if(!error) {
        out.println(getStatusMsg(status, agentName));	   
        if(replyHtml) {
          out.print("<p>");
        }
      }
      if(replyHtml) {
        out.println(getFooter());
      }
      out.flush();
      out.close();
    }
  
  private String getStatusMsg(int status, String uId) {
    StringBuffer sb = new StringBuffer();
    if(status==1) {
      sb.append("Successfully Revoked certificate : ");
    }
    else if(status==-2) {
      sb.append(" Certificate has already been revoked  : ");
    }
    else if(status==-3) {
      sb.append("Not Enough privileges to Revoke CA  Certificate  : ");
    }
    else {
      sb.append("Error in  Revoking  certificate : ");
    }
    sb.append(uId);
    return sb.toString(); 
  }
  
  private String getHeaderWithScript() {
    return HEADER_WITH_SCRIPT;
  }
  
  private String getHeader() {
    return "<html><body>"; 
  }
  private String getFooter() {
    return "</body></html>"; 
  }
  
  private String appendForm(String posturl, String caDNName, String domain) {
    
    StringBuffer sb=new StringBuffer();
    sb.append("<form name=\"certlist\" action=\"" + posturl
              + "\" method=\"post\">");
    sb.append("<input type=\"hidden\" name=\"cadnname\" value=\""
              + caDNName + "\">");
    sb.append("<input type=\"hidden\" name=\"domain\" value=\""
              + domain + "\">");
    sb.append("<a Href=\"javascript:submitme(document.certlist)\">"
              + "Back to List "+"</a></form>");
    return sb.toString();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException
    {
      PrintWriter out=res.getWriter();
      res.setContentType("text/html");
    
      if(context==null)
        {
          out.println(" got context as null");
        }
      /*Enumeration enumn= context.getServletNames();
        for(;enumn.hasMoreElements();)
        {
	String propname=(String)enumn.nextElement();
       	out.println(" Got servlet  name :"+propname );
        }
      */
      Enumeration enum = context.getAttributeNames();
      while(enum.hasMoreElements())
        {
          String propname=(String)enum.nextElement();
          out.println(" Got propert name :"+propname);
          log.debug(" Got propert name :"+propname);
          out.flush();
          if((propname.startsWith("java"))||(propname.startsWith("org.apache"))) {
            continue;
          }
          String value=(String )context.getAttribute(propname);
          log.debug(" property value :"+ value);
          out.println(" property value :"+ value);
        }
    }

  public String getServletInfo()
    {
      return("Displaying details of certificate with give hash map");
    }

  public String createtable(LdapEntry[] ldapentries)
    {
      StringBuffer sb=new StringBuffer();
      sb.append("<table align=\"center\">\n");
      sb.append("<TR><TH> DN-Certificate </TH><TH> Status </TH><TH> DN-Signed By </TH></TR>\n");
      for(int i = 0 ; i < ldapentries.length ; i++) {
        sb.append("<TR><TD><a Href=\"../CertificateDetails?distinguishedName="
                  + ldapentries[0].getUniqueIdentifier() + "\">" 
                  + ldapentries[0].getCertificate().getSubjectDN().getName()
                  + "</a><TD>\n");
        //sb.append("<TD>" + ldapentries[0].getStatus()+"</TD>\n" );
        sb.append("<TD>" + ldapentries[0].getCertificate().getIssuerDN().getName()
                  +"</TD></TR>\n");

      }
      sb.append("</table>");
      return sb.toString();
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
