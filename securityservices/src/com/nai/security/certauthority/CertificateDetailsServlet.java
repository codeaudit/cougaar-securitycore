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
      }
     protected void doGet(HttpServletRequest req,HttpServletResponse res)throws ServletException, IOException
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
        X509CertImpl certimpl;
        try
        {
                certimpl=new X509CertImpl(ldapentry.getCertificate().getTBSCertificate());
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
       out.println(certimpl.toString());
       out.println("<input type=\"button\" value=\"Revoke Certificate \" onClick=\"submit\">");
       out.println("</form>");
       out.println("</body></html>");
       out.flush();
       out.close();
     }

        public String getServletInfo()
        {
          return("Displaying details of certificate with give hash map");
        }
        public String createtable(Vector ldapentryvector)
        {
                StringBuffer sb=new StringBuffer();
                LdapEntry ldapentry=null;
                sb.append("<table align=\"center\">\n");
                sb.append("<TR><TH> DN-Certificate </TH><TH> Status </TH><TH> DN-Signed By </TH></TR>\n");
                for(Enumeration enum =ldapentryvector.elements();enum.hasMoreElements();)
                {
                        ldapentry=(LdapEntry)enum.nextElement();
                        sb.append("<TR><TD><a Href=\"../CertificateDetails?hash="+ldapentry.getHash() +"\">"+ldapentry.getCertificate().getSubjectDN().getName()+"</a><TD>\n");
                        sb.append("<TD>"+ldapentry.getStatus()+"</TD>\n" );
                        sb.append("<TD>"+ldapentry.getCertificate().getIssuerDN().getName()+"</TD></TR>\n");

                }
                sb.append("</table>");
                return sb.toString();
        }


}





