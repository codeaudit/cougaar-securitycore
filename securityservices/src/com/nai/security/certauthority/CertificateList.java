package com.nai.security.certauthority;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.X509Certificate;
public class CertificateList extends  HttpServlet
{
  private LDAPCert ldapcert=null;

    public void init(ServletConfig config) throws ServletException
    {

    }

      public void doPost (HttpServletRequest  req, HttpServletResponse res) throws ServletException,IOException
      {
      }
     protected void doGet(HttpServletRequest req,HttpServletResponse res)throws ServletException, IOException
     {
       res.setContentType("Text/HTML");
       ldapcert= new LDAPCert();
       PrintWriter out=res.getWriter();
       out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
       out.println("<html>");
       out.println("<head>");
       out.println("<title>Certificate List from Ldap </title>");
       out.println("</head>");
       out.println("<body>");
        out.println("<H2> Certificate List from Ldap</H2>");
        out.println(createtable(ldapcert.getCertificates()));
      out.println("</body></html>");
        out.flush();
       out.close();
     }

        public String getServletInfo()
        {
          return("Accepts signing request and returns signed certificate");
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

