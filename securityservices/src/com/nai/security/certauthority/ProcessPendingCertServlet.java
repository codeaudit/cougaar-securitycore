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

public class ProcessPendingCertServlet extends  HttpServlet
{
  private CaPolicy caPolicy = null;            // the policy of the CA
  private CertDirectoryServiceCA caOperations=null;
  private ConfParser confParser = null;

  protected boolean debug = false;
  javax.servlet.ServletContext context=null;

  public void init(ServletConfig config) throws ServletException
  {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    context=config.getServletContext();
    String confpath=(String)context.getAttribute("org.cougaar.security.crypto.config");
    confParser = new ConfParser(confpath, true);
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    PrintWriter out=res.getWriter();
    res.setContentType("Text/HTML");
    String alias=req.getParameter("alias");
    String role=req.getParameter("role");
    String cadnname=req.getParameter("cadnname");
    out.println("<html>");
    out.println("<body>");

    if((alias==null)||(alias=="")) {
      out.println("Error in getting the certificate alias");
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
    }
    catch (Exception e) {
      out.print("Unable to read policy file: " + e);
      out.flush();
      out.close();
      return;
    }

    String actionType = req.getParameter("actiontype");
    // 0 is deny, 1 is approve, -1 is unknown status
    if (actionType != null) {
      // retrieve pending certificate
      X509Certificate  certimpl;
      try {
        //certimpl=ldapentries[0].getCertificate();
	String certpath=(String)context.getAttribute("org.cougaar.security.CA.certpath");
	String confpath=(String)context.getAttribute("org.cougaar.security.crypto.config");

        PendingCertCache pendingCache = PendingCertCache.getPendingCache(cadnname, role, certpath, confpath);
        certimpl = (X509Certificate)
          pendingCache.getCertificate(caPolicy.pendingDirectory, alias);

        if (actionType.indexOf("Approve") >= 0) {
          caOperations.publishCertificate(certimpl,CertificateUtility.EntityCert,null);
          out.println("Certificate is now approved: " +
            certimpl.getSubjectDN().getName());
          // need to move to approved directory
          pendingCache.moveCertificate(
            caPolicy.pendingDirectory, caPolicy.x509CertDirectory, alias);
        }
        if (actionType.indexOf("Deny") >= 0) {
          out.println("Certificate is denied: " +
            certimpl.getSubjectDN().getName());
          // need to move to denied directory
          pendingCache.moveCertificate(
            caPolicy.pendingDirectory, caPolicy.deniedDirectory, alias);
        }
      }
      catch (Exception exp) {
        out.println("error-----------  "+exp.toString());
        out.flush();
        out.close();
        return;
      }

    }
    out.println("<p><a href=\"../servlet/pendingcert\"> Back to Pending Certificate List ></a>");
    out.println("</body>");
    out.println("</html>");

  }
  protected void doGet(HttpServletRequest req,HttpServletResponse res)throws ServletException, IOException
  {
  }

  public String getServletInfo()
  {
    return("Process the order to either deny or approve a pending certificate.");
  }


}

