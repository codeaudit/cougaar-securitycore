package com.nai.security.certauthority;

import java.io.*;
import java.util.*;

import javax.servlet.*;
import javax.servlet.http.*;

import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.jdom.input.*;


public class CertificateSigningRequest extends  HttpServlet
{
  private KeyManagement signer;

  public void init(ServletConfig config) throws ServletException
  {
        super.init(config);
        String file= config.getInitParameter("configfile");;
         try
             {
                SAXBuilder builder = new SAXBuilder();
                Document doc = builder.build(new File(file));
                Element root = doc.getRootElement();
                setjavaproperty(root);
             }
             catch(org.jdom.JDOMException jdexp)
             {
                 jdexp.printStackTrace();
             }
  }
  public void setjavaproperty(Element root)
  {
    javax.servlet.ServletContext context=null;
    context=getServletContext();
    List Children = root.getMixedContent();
    Iterator propertyIterator = Children.iterator();
         // Iterate through javaproperty
        while (propertyIterator.hasNext())
        {
            Object o = propertyIterator.next();
            if (o instanceof Element && ((Element)o).getName().equals("servletjavaproperties"))
            {
                Element propertyelement = (Element)o;
                String propertyName =  propertyelement.getChildText("propertyname");
                String propertyValue = propertyelement.getChildText("propertyvalue");
                if((propertyName==null )||(propertyValue==null))
                {
                    System.out.println("wrong xml format error");
                    return;
                }
                try
                {
                        System.setProperty(propertyName,propertyValue);
			//System.out.println("setting property name :"+propertyName);
			//System.out.println("setting property value ::"+propertyValue);
			context.setAttribute(propertyName,(Object)propertyValue);
		       
                }
                catch(SecurityException sexp)
                {
                       sexp.printStackTrace();
                }
            }
        }
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res) throws ServletException,IOException
  {
    String pkcs=null;
    String type=null;
    String CA_DN_name=null;
    //System.out.println("got post request");
    String data;
    //res.setContentType("text/html");
    //  PrintWriter out=res.getWriter();
    CA_DN_name =(String)req.getParameter("dnname");
    ByteArrayInputStream bytestream=null;
    PrintStream printstream=new PrintStream(res.getOutputStream());
    byte [] bytedata=null;
    if(( CA_DN_name==null)||( CA_DN_name=="")) {
      printstream.print("Error ---Unknown  type CA dn name :");
      printstream.flush();
      printstream.close();
      return;
    }
    try {
      signer=new KeyManagement(CA_DN_name);
    }
    catch (Exception exp) {
      printstream.print("Error ---" + exp.toString());
      printstream.flush();
      printstream.close();
      return;
    }
    type=req.getParameter("pkcs");
    if((type==null)||(type==""))
      {
	printstream.print("Error --- Unknown pkcs type:");
	printstream.flush();
	printstream.close();
	return;
      }
    pkcs=(String)req.getParameter("pkcsdata");
    try
      {
	if(type.equalsIgnoreCase("pkcs7"))
	  {
	    bytedata=pkcs.getBytes();
	    bytestream=new ByteArrayInputStream(bytedata);
	    signer.processX509Request(printstream,(InputStream)bytestream);

	  }
	else if(type.equalsIgnoreCase("pkcs10"))
	  {
	    bytedata=pkcs.getBytes();
	    bytestream=new ByteArrayInputStream(bytedata);
	    signer.processPkcs10Request(printstream,(InputStream)bytestream);


	  }
	else
	  {
	    printstream.print("Error ----Got a wrong parameter for type"+type);
	  }
      }
    catch (Exception  exp)
      {
	printstream.print("Error ------"+exp.toString());
	printstream.flush();
	printstream.close();

      }
    finally
      {
            printstream.flush();
             printstream.close();
        }

  }
  protected void doGet(HttpServletRequest req,HttpServletResponse res)throws ServletException, IOException
  {
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

