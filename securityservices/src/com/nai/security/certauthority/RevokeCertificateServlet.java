package com.nai.security.certauthority;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.X509Certificate;
import sun.security.x509.*;

import com.nai.security.crypto.ConfParser;
import com.nai.security.crypto.CertificateUtility;
import com.nai.security.crypto.ldap.CertDirectoryServiceCA;
import com.nai.security.crypto.ldap.CertDirectoryServiceClient;
import com.nai.security.crypto.ldap.CertDirectoryServiceFactory;
import com.nai.security.crypto.ldap.LdapEntry;
import com.nai.security.policy.CaPolicy;

public class RevokeCertificateServlet extends  HttpServlet
{
  private CaPolicy caPolicy = null;            // the policy of the CA
  private CertDirectoryServiceCA caOperations=null;
  private CertDirectoryServiceClient certificateFinder=null;
  private ConfParser confParser = null;

  protected boolean debug = false;

  public void init(ServletConfig config) throws ServletException
  {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    confParser = new ConfParser();
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    PrintWriter out=res.getWriter();
    res.setContentType("Text/HTML");
    String distinguishedName=req.getParameter("distinguishedName");
    String role=req.getParameter("role");
    String cadnname=req.getParameter("cadnname");
    out.println("<html>");
    out.println("<body>");

    if((distinguishedName==null)||(distinguishedName=="")) {
      out.println("Error in getting the certificate distinguishedName");
      out.flush();
      out.close();
      return;
    }
    if((cadnname==null)||(cadnname=="")) {
      out.println("Error in getting the CA's DN ");
      out.flush();
      out.close();
      return;
    }

    try {
      caPolicy = confParser.readCaPolicy(cadnname, role);
      caOperations = 
	CertDirectoryServiceFactory.getCertDirectoryServiceCAInstance(
				       caPolicy.ldapType, caPolicy.ldapURL);
      certificateFinder = 
	CertDirectoryServiceFactory.getCertDirectoryServiceClientInstance(
				       caPolicy.ldapType, caPolicy.ldapURL);
    }
    catch (Exception e) {
      out.print("Unable to read policy file: " + e);
      out.flush();
      out.close();
      return;
    }

    String filter = "(dn=" + distinguishedName + ")";
    LdapEntry[] ldapentries = certificateFinder.searchWithFilter(filter);
    if(ldapentries==null) {
      out.println("Error in retrieving certificate from LDAP ");
      out.flush();
      out.close();
      return;
    }
    if (debug) {
      System.out.println("Revoking cert with filter:" + filter);
      System.out.println(ldapentries.length + " certificates satisfy this filter");
    }
    if (ldapentries.length != 1) {
      out.println("Error: there are multiple certificates with the same UID");
      out.flush();
      out.close();
      return;
    }
     
    boolean status= caOperations.revokeCertificate(ldapentries[0]);
    if(status) {
      out.println("Successfully Revoked certificate :"
		  +ldapentries[0].getCertificate().getSubjectDN().getName() );
      out.println("<p>");
    }
    else {
      out.println("Error in  Revoking  certificate :"
		  + ldapentries[0].getCertificate().getSubjectDN().getName() );
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

  public String createtable(LdapEntry[] ldapentries)
  {
    StringBuffer sb=new StringBuffer();
    sb.append("<table align=\"center\">\n");
    sb.append("<TR><TH> DN-Certificate </TH><TH> Status </TH><TH> DN-Signed By </TH></TR>\n");
    for(int i = 0 ; i < ldapentries.length ; i++) {
      sb.append("<TR><TD><a Href=\"../CertificateDetails?distinguishedName="
		+ ldapentries[0].getUniqueIdentifier() + "\">" 
		+ ldapentries[0].getCertificate().getSubjectDN().getName()
		+ "</a><TD>\n");
      //sb.append("<TD>" + ldapentries[0].getStatus()+"</TD>\n" );
      sb.append("<TD>" + ldapentries[0].getCertificate().getIssuerDN().getName()
		+"</TD></TR>\n");

    }
    sb.append("</table>");
    return sb.toString();
  }


}

