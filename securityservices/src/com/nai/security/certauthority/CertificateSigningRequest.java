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

import org.cougaar.util.*;

import org.w3c.dom.*;

public class CertificateSigningRequest extends  HttpServlet
{
  private KeyManagement signer;
  javax.servlet.ServletContext context=null;
  
  public void init(ServletConfig config) throws ServletException
  {
    super.init(config);
    String file= config.getInitParameter("configfile");
    ConfigFinder confFinder = new ConfigFinder();
    try {
      Document doc = confFinder.parseXMLConfigFile(file);
      Element root = doc.getDocumentElement();
      setjavaproperty(root);
    }
    catch (IOException e) {
      System.out.println("Unable to read configFile: " + e);
    }
  }



  /** This convenience method returns the textual content of the named
      child element, or returns an empty String ("") if the child has no
      textual content. */
  private String getChildText(Element e, String tagName)
  {
    NodeList nodes = e.getElementsByTagName(tagName);
    if (nodes == null || nodes.getLength() == 0) {
      return null;
    }
    // Get first element
    Node child = nodes.item(0).getFirstChild();
    String val = null;
    if (child != null) {
      val = child.getNodeValue();
    }
    return val;
  }

  public void setjavaproperty(Element root)
  {
    //javax.servlet.ServletContext context=null;
    context=getServletContext();
    NodeList children = root.getChildNodes();

    // Iterate through javaproperty
    for (int i = 0 ; i < children.getLength() ; i++) {
      Node o = children.item(i);
      if (o instanceof Element &&
	  ((Element)o).getTagName().equals("servletjavaproperties")) {
	Element propertyelement = (Element)o;
	String propertyName =  getChildText(propertyelement,
					    "propertyname");
	String propertyValue = getChildText(propertyelement,
					    "propertyvalue");
	if((propertyName==null )||(propertyValue==null)) {
	  System.out.println("wrong xml format error");
	  return;
	}
	try {
	  if(propertyName.equalsIgnoreCase("org.cougaar.core.security.crypto.debug")) {
	    System.setProperty(propertyName,propertyValue);
	  }
	  else {
	     System.out.println("setting property name in context  :"+propertyName);
	       System.out.println("setting property value in context::"+propertyValue);
	    
	       context.setAttribute(propertyName,propertyValue);
	  }
	}
	catch(SecurityException sexp) {
	  sexp.printStackTrace();
	}
      }
    }
  }
  
  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    String pkcs=null;
    String type=null;
    String CA_DN_name=null;
    String role = null;

    String data;
    //res.setContentType("text/html");
    //  PrintWriter out=res.getWriter();
    CA_DN_name =(String)req.getParameter("dnname");
    role =(String)req.getParameter("role");
    ByteArrayInputStream bytestream=null;
    PrintStream printstream=new PrintStream(res.getOutputStream());
    byte [] bytedata=null;
    String certpath=(String)context.getAttribute("org.cougaar.security.CA.certpath");
    System.out.println(" cert path  is :"+certpath);
    
    String confpath=(String)context.getAttribute("org.cougaar.security.crypto.config");
    System.out.println(" Conf path  is :"+confpath);
    if(( CA_DN_name==null)||( CA_DN_name=="")) {
      printstream.print("Error ---Unknown  type CA dn name :");
      printstream.flush();
      printstream.close();
      return;
    }
    try  {
      if(( role==null)||( role==""))  {
	signer=new KeyManagement(CA_DN_name,null,certpath,confpath);
      }
      else  {
	signer=new KeyManagement(CA_DN_name,role,certpath,confpath);
	
      }
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
    try  {
      if(type.equalsIgnoreCase("pkcs7"))  {
	bytedata=pkcs.getBytes();
	bytestream=new ByteArrayInputStream(bytedata);
	signer.processX509Request(printstream,(InputStream)bytestream);
	
      }
      else if(type.equalsIgnoreCase("pkcs10"))  {
	bytedata=pkcs.getBytes();
	bytestream=new ByteArrayInputStream(bytedata);
	signer.processPkcs10Request(printstream,(InputStream)bytestream);
      }
      else  {
	printstream.print("Error ----Got a wrong parameter for type"+type);
      }
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
  
  protected void doGet(HttpServletRequest req,HttpServletResponse res)throws ServletException, IOException  {
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
    out.println("<tr ><td colspan=\"3\">");
    out.println("Role : <input name=\"role\" type=\"text\" value=\"\">");
    out.println(" <br> <br></td></tr>");
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
            
 
}

