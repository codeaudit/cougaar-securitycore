package com.nai.security.certauthority;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.X509Certificate;
import sun.security.x509.*;

public class RevokeCertificateServlet extends  HttpServlet
{
  private LdapEntry ldapentry=null;
  private KeyManagement keymanage=null;

    public void init(ServletConfig config) throws ServletException
    {

    }

      public void doPost (HttpServletRequest  req, HttpServletResponse res) throws ServletException,IOException
      {
       
        PrintWriter out=res.getWriter();
        res.setContentType("Text/HTML");
        String hash=req.getParameter("hash");
	String role=req.getParameter("role");
	String dnname=req.getParameter("dnname");
        out.println("<html>");
        out.println("<body>");

        if((hash==null)||(hash==""))
        {
                out.println("Error in getting the certificate hash");
                out.flush();
                out.close();
                return;
        }
	if((dnname==null)||(dnname==""))
        {
                out.println("Error in getting the CA's DN ");
                out.flush();
                out.close();
                return;
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
	  }
	 catch(Exception exp)
        {
                out.println("Error -------"+exp.toString());
                out.flush();
                out.close();
                return;
        }
        ldapentry=keymanage.getCertificate(hash);
     
       boolean status= keymanage.revokeCertificate(ldapentry.getCertificate());
       if(status)
        {
                out.println("Successfully Revoked certificate :"+ldapentry.getCertificate().getSubjectDN().getName() );
		out.println("<p>");
        }
        else
        {
                out.println("Error in  Revoking  certificate :"+ldapentry.getCertificate().getSubjectDN().getName() );
        }
        out.println("<a href=\"/certlist\"> Back to Certificate List ></a>");
        out.println("</body>");
        out.println("</html>");

      }
     protected void doGet(HttpServletRequest req,HttpServletResponse res)throws ServletException, IOException
     {

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

