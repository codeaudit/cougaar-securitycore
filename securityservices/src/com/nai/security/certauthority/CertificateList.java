package com.nai.security.certauthority;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.X509Certificate;
public class CertificateList extends  HttpServlet
{
  private KeyManagement keymanage=null;

    public void init(ServletConfig config) throws ServletException
    {

    }

      public void doPost (HttpServletRequest  req, HttpServletResponse res) throws ServletException,IOException
      {
       PrintWriter out=res.getWriter();
       String role=null;
       String dnname=null;
       dnname =(String)req.getParameter("dnname");
       role =(String)req.getParameter("role");
       if((dnname==null)||( dnname==""))
       {
        out.print("Error ---Unknown  type CA dn name :");
        out.flush();
        out.close();
        return;
       }
        try
        {
                if(( role==null)||( role==""))
                {
                        keymanage=new KeyManagement(dnname,null);
                }
                else
                {
                        keymanage=new KeyManagement(dnname,role);
                }
        }
        catch (Exception exp)
        {
                out.print("Error ---" + exp.toString());
                out.flush();
                out.close();
                return;
        }

       out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
       out.println("<html>");
       out.println("<head>");
       out.println("<title>Certificate List from Ldap </title>");
       out.println("</head>");
       out.println("<body>");
       out.println("<H2> Get Certificate List from Ldap</H2>");
       out.println("<table>");
       if((role==null)||(role==""))
	 {
	   out.println(createtable(keymanage.getCertificates(),dnname));
	 }
       else
	 {
	   out.println(createtable(keymanage.getCertificates(),dnname,role));
	 }
out.println("</body></html>");
        out.flush();
        out.close();
      }
     protected void doGet(HttpServletRequest req,HttpServletResponse res)throws ServletException, IOException
     {
       res.setContentType("Text/HTML");
       PrintWriter out=res.getWriter();
       out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
       out.println("<html>");
       out.println("<head>");
       out.println("<title>Certificate List from Ldap </title>");
       out.println("</head>");
       out.println("<body>");
       out.println("<H2> Get Certificate List from Ldap</H2>");
       out.println("<table>");
        out.println("<form action=\"\" method =\"post\">");
        out.println("<tr ><td colspan=\"3\">");
        out.println("Role <input name=\"role\" type=\"text\" value=\"\">");
        out.println(" <br> <br></td></tr>");
        out.println("<tr ><td colspan=\"3\">");
        out.println("DN for CA <input name=\"dnname\" type=\"text\" value=\"\">");
        out.println(" <br> <br></td></tr>");
        out.println("</tr><tr><td></td><td><br><input type=\"submit\">&nbsp;&nbsp;&nbsp;");
        out.println("<input type=\"reset\"></td><td></td></tr>");
        out.println("</form></table>");
        out.println("</body></html>");
        out.flush();
        out.close();

     }

        public String getServletInfo()
        {
          return("List all certificate specified by role and CAS dn name");
        }
        public String createtable(Vector ldapentryvector,String dnname)
        {
                StringBuffer sb=new StringBuffer();
                LdapEntry ldapentry=null;
                sb.append("<table align=\"center\" boder=\"2\">\n");
                sb.append("<TR><TH> DN-Certificate </TH><TH> Status </TH><TH> DN-Signed By </TH></TR>\n");
                for(Enumeration enum =ldapentryvector.elements();enum.hasMoreElements();)
                {
                        ldapentry=(LdapEntry)enum.nextElement();
                        sb.append("<TR><TD><a Href=\"../certdetails?hash="+ldapentry.getHash() +"&dnname="+dnname+"\">"+ldapentry.getCertificate().getSubjectDN().getName()+"</a></TD>\n");
                        sb.append("<TD>"+ldapentry.getStatus()+"</TD>\n" );
                        sb.append("<TD>"+ldapentry.getCertificate().getIssuerDN().getName()+"</TD></TR>\n");

                }
                sb.append("</table>");
                return sb.toString();
        }

 public String createtable(Vector ldapentryvector,String dnname,String role)
        {
                StringBuffer sb=new StringBuffer();
                LdapEntry ldapentry=null;
                sb.append("<table align=\"center\" boder=\"2\">\n");
                sb.append("<TR><TH> DN-Certificate </TH><TH> Status </TH><TH> DN-Signed By </TH></TR>\n");
                for(Enumeration enum =ldapentryvector.elements();enum.hasMoreElements();)
                {
                        ldapentry=(LdapEntry)enum.nextElement();
                        sb.append("<TR><TD><a Href=\"../certdetails?hash="+ldapentry.getHash() +"&dnname="+dnname+"&role="+role+"\">"+ldapentry.getCertificate().getSubjectDN().getName()+"</a></TD>\n");
                        sb.append("<TD>"+ldapentry.getStatus()+"</TD>\n" );
                        sb.append("<TD>"+ldapentry.getCertificate().getIssuerDN().getName()+"</TD></TR>\n");

                }
                sb.append("</table>");
                return sb.toString();
        }


}



