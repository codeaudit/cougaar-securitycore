package com.nai.security.certauthority;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.X509Certificate;
import sun.security.x509.*;

public class RevokeCertificateServlet extends  HttpServlet
{
  private LDAPCert ldapcert=null;
  private LdapEntry ldapentry=null;
  private KeyManagement keymanage=null;

    public void init(ServletConfig config) throws ServletException
    {

    }

      public void doPost (HttpServletRequest  req, HttpServletResponse res) throws ServletException,IOException
      {
        ldapcert= new LDAPCert();
        PrintWriter out=res.getWriter();
        res.setContentType("Text/HTML");
        String hash=req.getParameter("hash");
        out.println("<html>");
        out.println("<body>");

        if((hash==null)||(hash==""))
        {
                out.println("Error in getting the certificate hash");
		out.flush();
		out.close();
		return;
        }
        //ldapentry=ldapcert.getCertificate(hash);
	try
	{
		
        	keymanage=new KeyManagement(ldapentry.getCertificate().getIssuerDN().getName());
	}
	catch(Exception exp)
	{
                out.println("Error -------"+exp.toString());
		out.flush();
		out.close();
		return;
		
	}	
       boolean status= keymanage.revokeCertificate(ldapentry.getCertificate());
       if(status)
        {
                out.println("Successfully Revoked certificate :"+ldapentry.getCertificate().getSubjectDN().getName() );
        }
        else
        {
                out.println("Error in  Revoking  certificate :"+ldapentry.getCertificate().getSubjectDN().getName() );
        }
        out.println("<a href=\"../CertificateList\"> Back to Certificate List ></a>");
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

