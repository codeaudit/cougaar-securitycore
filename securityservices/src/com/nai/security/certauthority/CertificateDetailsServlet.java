package com.nai.security.certauthority;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.X509Certificate;
import sun.security.x509.*;

public class CertificateDetailsServlet extends  HttpServlet
{
  private KeyManagement keymanage=null;
  private LdapEntry ldapentry=null;

    public void init(ServletConfig config) throws ServletException
    {

    }

      public void doPost (HttpServletRequest  req, HttpServletResponse res) throws ServletException,IOException
      {
        res.setContentType("Text/HTML");

       String hash=null;
       String role=null;
       String dnname=null;


       PrintWriter out=res.getWriter();
	hash=req.getParameter("hash");
	role=req.getParameter("role");
	dnname=req.getParameter("dnname");
	if((dnname==null)||(dnname==""))
	  {
	    out.print("Error in dn name ");
	    out.flush();
	    out.close();
	  }
          try
          {
                if((role==null)||(role==""))
                {
                keymanage=new KeyManagement(dnname,null);

                }
                else
                {
                keymanage=new KeyManagement(dnname,role);
                }

                if((hash==null)||(hash==""))
                {
                out.print("Error in hash ");
                out.flush();
                out.close();
                }
          }
          catch(Exception exp)
                {
                        out.println("Error in creating keymanagement");
                        out.flush();
                        out.close();
                        return;
                }


       ldapentry=keymanage.getCertificate(hash);
       if(ldapentry==null)
       {
           out.println("error in retrieving certificate from LDAP ");
           out.flush();
           out.close();
           return;

       }
        X509Certificate  certimpl;
        try
        {
                certimpl=ldapentry.getCertificate();
        }
        catch (Exception exp)
        {
           out.println("error-----------  "+exp.toString());
           out.flush();
           out.close();
           return;
        }
       out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
       out.println("<html>");
       out.println("<head>");
       out.println("<title>Certificate details </title>");
       out.println("</head>");
       out.println("<body>");
       out.println("<H2> Certificate Details</H2><BR>");
       out.println("<form name=\"revoke\" action=\"../RevokeCertificate\" method=\"post\">");
       out.println("<input type=\"hidden\" name=\"hash\" value=\""+ldapentry.getHash()+"\">");
       if((role==null)||(role==""))
       {
	 out.println("<input type=\"hidden\" name=\"role\" value=\""+role+"\">");
       }
       out.println("<input type=\"hidden\" name=\"dnname\" value=\""+dnname+"\">");
       out.println("<p>");
       System.out.println(certimpl.toString());
       out.println(certimpl.toString());
       out.println("<input type=\"button\" value=\"Revoke Certificate \" onClick=\"submit\">");
       out.println("</form>");
       out.println("</body></html>");
       out.flush();
       out.close();
      }
     protected void doGet(HttpServletRequest req,HttpServletResponse res)throws ServletException, IOException
     {

     }

        public String getServletInfo()
        {
          return("Displaying details of certificate with give hash map");
        }

}





