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
		System.out.println("creating keymanagement with role null");
		keymanage=new KeyManagement(dnname,null);

	      }
	    else
	      {
		System.out.println("creating keymanagement with role:"+role);
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
       out.println("<form name=\"revoke\" action=\"/CA/servlet/revokecertificate\" method=\"post\">");
       out.println("<input type=\"hidden\" name=\"hash\" value=\""+ldapentry.getHash()+"\">");
       if((role==null)||(role==""))
       {
	 System.out.println("got role as null or empty in certificate details:::::++++");
	
       }
       else{
	  out.println("<input type=\"hidden\" name=\"role\" value=\""+role+"\">");
       }
       out.println("<input type=\"hidden\" name=\"dnname\" value=\""+dnname+"\">");
       out.println("<p>");
        out.println("<p>");
       out.println("<b>Version&nbsp;&nbsp;&nbsp;:</b>"+certimpl.getVersion());
       out.println("<br>");
       out.println("<b>Subject&nbsp;&nbsp;&nbsp;:</b>"+certimpl.getSubjectDN().getName());
       out.println("<br>");
       out.println("<b>Signature Algorithm &nbsp;&nbsp;&nbsp;:</b>"+certimpl.getSigAlgName()+ ",<b>&nbsp;OID&nbsp; :</b>"+certimpl.getSigAlgOID());
       out.println("<br>");
       out.println("<b>Key&nbsp;&nbsp;&nbsp;:</b>"+keymanage.toHexinHTML(certimpl.getPublicKey().getEncoded()));
       out.println("<br>");
       out.println("<b>Validity&nbsp;&nbsp;&nbsp;:</b>");
       out.println("<br>");
       out.println("<b>&nbsp;&nbsp;&nbsp;From &nbsp;:</b>"+certimpl.getNotBefore().toString());
       out.println("<br>");
       out.println("<b>&nbsp;&nbsp;&nbsp;To &nbsp;:</b>"+certimpl.getNotAfter().toString());
       out.println("<br>");
       out.println("<b>Issuer&nbsp;&nbsp;&nbsp;:</b>"+certimpl.getIssuerDN().getName());
       out.println("<br>");
       out.println("<b>Serial No &nbsp;&nbsp;&nbsp;:</b>"+certimpl.getSerialNumber());
       out.println("<br>");
       out.println("<b>Algorithm&nbsp;&nbsp;&nbsp;:</b>"+certimpl.getPublicKey().getAlgorithm());
       out.println("<br>");
       out.println("<b>Signature &nbsp;&nbsp;&nbsp;:</b>"+keymanage.toHexinHTML(certimpl.getSignature()));
       out.println("<br>");
       out.println("<br>");
       out.println("<br>");
       out.println("<input type=\"submit\" value=\"Revoke Certificate \">");
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





