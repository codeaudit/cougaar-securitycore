package com.nai.security.certauthority;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
public class CertificateSigningRequest extends  HttpServlet
{
  private KeyManagement signer;

    public void init(ServletConfig config) throws ServletException
    {

    }

      public void doPost (HttpServletRequest  req, HttpServletResponse res) throws ServletException,IOException
      {
        String pkcs=null;
	String type=null;
	String CA_DN_name=null;
        System.out.println("got post request");
        String data;
        res.setContentType("text/html");
      //  PrintWriter out=res.getWriter();
        CA_DN_name =(String)req.getParameter("dnname");
        ByteArrayInputStream bytestream=null;
        PrintStream printstream=new PrintStream(res.getOutputStream());
        byte [] bytedata=null;
        if(( CA_DN_name==null)||( CA_DN_name==""))
        {
                printstream.print("Error ---Unknown  type CA dn name :");
                printstream.flush();
                printstream.close();
                return;
        }
        signer=new KeyManagement(CA_DN_name);
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


        printstream.flush();
        printstream.close();
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

