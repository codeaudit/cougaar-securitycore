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



package com.nai.security.certauthority;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.X509Certificate;
import sun.security.x509.*;

import java.security.PrivateKey;
import com.nai.security.crypto.ConfParser;
import com.nai.security.crypto.CertificateUtility;
import com.nai.security.crypto.ldap.CertDirectoryServiceCA;
import com.nai.security.crypto.ldap.CertDirectoryServiceClient;
import com.nai.security.crypto.ldap.CertDirectoryServiceFactory;
import com.nai.security.crypto.ldap.LdapEntry;
import com.nai.security.policy.CaPolicy;
import com.nai.security.crypto.MultipleEntryException;

public class RevokeCertificateServlet extends  HttpServlet
{
  /* private CaPolicy caPolicy = null;            // the policy of the CA
  private CertDirectoryServiceCA caOperations=null;
  private CertDirectoryServiceClient certificateFinder=null;
  private ConfParser confParser = null;
  */
  private KeyManagement keymanagement=null;
  javax.servlet.ServletContext context=null;
  protected boolean debug = false;


  public void init(ServletConfig config) throws ServletException
  {
    //confParser = new ConfParser();
     
    context=config.getServletContext();
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    if(debug)
      System.out.println(" context is :"+ context.toString());

  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    PrintWriter out=res.getWriter();
    res.setContentType("Text/HTML");
   
    String distinguishedName=req.getParameter("distinguishedName");
    String role=req.getParameter("role");
    String cadnname=req.getParameter("cadnname");
   
    String certpath=(String)context.getAttribute("org.cougaar.security.CA.certpath");
    String confpath=(String)context.getAttribute("org.cougaar.security.crypto.config");
    
    out.println("<html>");
     out.println("<script language=\"javascript\">");
    out.println("function submitme(form)");
    out.println("{ form.submit()}</script>");
    out.println("</head>");
    out.println("<body>");

    if((distinguishedName==null)||(distinguishedName=="")) {
      out.println("Error in getting the certificate distinguishedName");
      out.flush();
      out.close();
      return;
    }
    if((cadnname==null)||(cadnname=="")) {
      out.println("Error in getting the CA's DN ");
      out.flush();
      out.close();
      return;
    }
    int status ;
     String uri = req.getRequestURI();
    String certlistUri = uri.substring(0, uri.lastIndexOf('/')) + "/certlist";
    try {
    
    keymanagement=new KeyManagement(cadnname,role,certpath,confpath);
    /*try {
      caPolicy = confParser.readCaPolicy(cadnname, role);
      caOperations = 
	CertDirectoryServiceFactory.getCertDirectoryServiceCAInstance(
				       caPolicy.ldapType, caPolicy.ldapURL);
      certificateFinder = 
	CertDirectoryServiceFactory.getCertDirectoryServiceClientInstance(
				       caPolicy.ldapType, caPolicy.ldapURL);
    */
    String uniqueIdentifier=distinguishedName;
    status=keymanagement.revokeCertificate(cadnname,uniqueIdentifier);
    }
    catch (MultipleEntryException multipleexp) {
      out.print("Multiple entry found for : " + multipleexp.getMessage());
       out.println(appendForm(certlistUri,cadnname,role));

      out.flush();
      out.close();
      return;
    }
     catch (Exception generalexp) {
      out.print("Error has occured due to  following reason  : " +generalexp.getMessage());
     out.println(appendForm(certlistUri,cadnname,role));  
      out.flush();
      out.close();
      return;
    }
    
 
    if(status==1) {
      out.println("Successfully Revoked certificate :"
		  + distinguishedName);
      out.println("<p>");
    }
    else if(status==-2) {
      out.println(" Certificate has already been revoked   :"
		  + distinguishedName);
      out.println("<p>");
    }
    else if(status==-3) {
       out.println("Not Enough privileges to Revoke CA  Certificate  :"
		  + distinguishedName);
      out.println("<p>");
    }
    else {
      out.println("Error in  Revoking  certificate :"
		  + distinguishedName);
    }
  
    
    out.println(appendForm(certlistUri,cadnname,role));
    out.println("</body>");
    out.println("</html>");

  }
  private String appendForm(String posturl, String caDNName, String role) {
    
    StringBuffer sb=new StringBuffer();
     sb.append("<form name=\"certlist\" action=\"" +posturl + "\" method=\"post\">");
     sb.append("<input type=\"hidden\" name=\"cadnname\" value=\""
		+caDNName + "\">");
     sb.append("<input type=\"hidden\" name=\"role\" value=\"" + role + "\">");
     sb.append("<a Href=\"javascript:submitme(document.certlist)\">"
		+ "Back to List "+"</a></form>");
     return sb.toString();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)throws ServletException, IOException
  {
     PrintWriter out=res.getWriter();
    res.setContentType("Text/HTML");
    
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
    Enumeration enum =context.getAttributeNames();
    for(;enum.hasMoreElements();)
      {
	String propname=(String)enum.nextElement();
	out.println(" Got propert name :"+propname);
	System.out.println(" Got propert name :"+propname);
	out.flush();
	if((propname.startsWith("java"))||(propname.startsWith("org.apache"))) {
	  continue;
	}
	String value=(String )context.getAttribute(propname);
	System.out.println(" property value :"+ value);
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


}

