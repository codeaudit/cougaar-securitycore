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
        }
        //ldapentry=ldapcert.getCertificate(hash);
        keymanage=new KeyManagment(ldapentry.getCertificate().getIssuerDN().getName());
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


       String query=req.getQueryString();
       String hash=null;
       PrintWriter out=res.getWriter();
       if((query==null)||(query==""))
       {
        out.println("error in request");
        out.flush();
        out.close();
        return;

       }
        int startindex=-1;
       if(query.startsWith("?hash"))
       {
                startindex=query.indexOf('=');
                if((startindex==-1)||(startindex+1>=query.length()) )
                {
                        out.println("error in request format ");
                        out.flush();
                        out.close();
                        return;

                }
                hash=query.substring(startindex+1,query.length());


       }
       ldapentry=ldapcert.getCertificate(hash);
       if(ldapentry==null)
       {
           out.println("error in retrieving certificate from LDAP ");
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
       out.println("<form name=\"revoke\" action=\"../RevokeCertificate\" nethod=\"post\">");
       out.println("<input type=\"hidden\" name=\"hash\" value=\""+ldapentry.getHash()+"\">");

       X509CertImpl certimpl=new X509CertImpl(ldapentry.getCertificate().getTBSCertificate());
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

