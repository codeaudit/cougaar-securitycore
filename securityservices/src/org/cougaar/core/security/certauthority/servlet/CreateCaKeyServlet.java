/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */

package org.cougaar.core.security.certauthority.servlet;

import java.io.*;
import java.util.*;
import java.security.Principal;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.X509Certificate;
import sun.security.x509.*;
import javax.security.auth.x500.X500Principal;

// Cougaar core infrastructure
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Overlay
import org.cougaar.core.service.identity.*;

// Cougaar security services
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.crypto.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.crypto.ldap.CertDirectoryServiceFactory;
import org.cougaar.core.security.crypto.ldap.LdapEntry;
import org.cougaar.core.security.certauthority.*;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.services.identity.*;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.config.*;

public class CreateCaKeyServlet
  extends  HttpServlet
{
  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;
  private KeyRingService keyRingService= null;
  private LoggingService log;

  protected boolean debug = false;

  private SecurityServletSupport support;
  private AgentIdentityService agentIdentity;

  public CreateCaKeyServlet(SecurityServletSupport support) {
    this.support = support;
    log = (LoggingService)
      support.getServiceBroker().getService(this,
			       LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
  {
    secprop = support.getSecurityProperties(this);
    debug = (Boolean.valueOf(secprop.getProperty(secprop.CRYPTO_DEBUG,
						"false"))).booleanValue();
    keyRingService = (KeyRingService)
      support.getServiceBroker().getService(this,
					    KeyRingService.class,
					    null);
    configParser = (ConfigParserService)
      support.getServiceBroker().getService(this,
					    ConfigParserService.class,
					    null);
  }

  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    String caCN =(String)req.getParameter("CN");
    String caOU =(String)req.getParameter("OU");
    String caO  =(String)req.getParameter("O");
    String caL  =(String)req.getParameter("L");
    String caST =(String)req.getParameter("ST");
    String caC  =(String)req.getParameter("C");

    String ldapURL = (String)req.getParameter("LDAPurl");
    String validity = (String)req.getParameter("Validity");
    String envelope = (String)req.getParameter("timeEnvelope");
    String requirePending = (String)req.getParameter("RequirePending");
    String keySize = (String)req.getParameter("KeySize");
    String nodeIsSigner = (String)req.getParameter("nodeIsSigner");

    String caDN = "cn=" + caCN
      + ", ou=" + caOU
      + ", o=" + caO
      + ", l=" + caL
      + ", st=" + caST
      + ", c=" + caC
      + ", t=" + DirectoryKeyStore.CERT_TITLE_CA;
    if (log.isDebugEnabled()) {
      log.debug("Creating CA key for: " + caDN);
    }

    // Build a hashtable of (attribute, value) pairs to replace
    // attributes with their value in a template XML file.
    Hashtable attributeTable = new Hashtable();
    attributeTable.put("distinguishedName", caDN);
    attributeTable.put("ldapURL", ldapURL);
    attributeTable.put("keysize", keySize);
    attributeTable.put("validity", validity);
    attributeTable.put("timeEnvelope", envelope);
    attributeTable.put("requirePending", requirePending);
    attributeTable.put("nodeIsSigner", nodeIsSigner);

    PrintWriter out=res.getWriter();
    try {
      X500Name dname = new X500Name(caDN);
    }
    catch (IOException e) {
      out.println("Unable to create CA certificate: " + e);
      e.printStackTrace(out);
      out.flush();
      out.close();
      return;
    }

    X500Principal p = new X500Principal(caDN);
    agentIdentity = (AgentIdentityService)
      support.getServiceBroker().getService(new CAIdentityClientImpl(p),
					    AgentIdentityService.class,
					    null);
    try {
      agentIdentity.acquire(null);
    }
    catch (Exception e) {
      out.println("Unable to generate CA key: " + e);
      e.printStackTrace(out);
      out.flush();
      out.close();
      return;
    }

    generateCaPolicy(attributeTable);

    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>CA key generation</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>CA key generation</H2>");
    out.println("CA key has been generated.<br><br>");
    out.println("CA private key has been stored in:<br>"
		+ keyRingService.getKeyStorePath());
    out.println("<br><br>CA certificate has been stored in:<br>"
		+ keyRingService.getCaKeyStorePath());
    out.println("<br></body></html>");
    out.flush();
    out.close();
  }

  private void generateCaPolicy(Hashtable attributeTable) {
    PolicyHandler ph = new PolicyHandler(configParser,
					 support.getServiceBroker());
    ph.addCaPolicy(attributeTable);
  }

  private void doCaForm(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    res.setContentType("Text/HTML");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>CA key generation</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>CA key generation</H2>");

    out.println("<table>");
    out.println("<b>CA X.509 Attributes</b>");
//    out.println("<TR><TH>Attribute</TH><TH>Value</TH></TR>\n");
    out.println("<form action=\"\" method =\"post\">");

    out.println("<tr><td>");
    out.println("Common Name:</td><td><input name=\"CN\" type=\"text\" value=\"\">");
    out.println("</td></tr>");

    out.println("<tr><td>");
    out.println("Organization unit:</td><td><input name=\"OU\" type=\"text\" value=\"\">");
    out.println("</td></tr>");

    out.println("<tr><td>");
    out.println("Organization:</td><td><input name=\"O\" type=\"text\" value=\"\">");
    out.println("</td></tr>");

    out.println("<tr><td>");
    out.println("Locality:</td><td><input name=\"L\" type=\"text\" value=\"\">");
    out.println("</td></tr>");

    out.println("<tr><td>");
    out.println("State:</td><td><input name=\"ST\" type=\"text\" value=\"\">");
    out.println("</td></tr>");

    out.println("<tr><td>");
    out.println("Country:</td><td><input name=\"C\" type=\"text\" value=\"\">");
    out.println("</td></tr>");

    // Policy parameters
    out.println("<br><br><b>Policy</b>");
    out.println("<tr><td>");
    out.println("LDAP URL:</td><td><input name=\"LDAPurl\" type=\"text\" value=\"\"></td>");
    out.println("<td><i>The directory where certificates will be published.<br>");
    out.println("Example:    <b>ldap://pear:389/dc=cougaar,dc=org</b></i></td>");
    out.println("</tr>");

    out.println("<tr><td>");
    out.println("Validity:</td><td><input name=\"Validity\" type=\"text\" value=\"\"></td>");
    out.println("<td><i>The default validity of a certificate issued by this CA<br>");
    out.println("Format:    <b>a1 y a2 M a3 d a4 h a5 m a6 s</b> ");
    out.println("where a1...a6 is a number<br>");
    out.println("y=year, M=month, d=day, h=hour, m=minute, s=second. At least one key is required<br>");
    out.println("</i></td></tr>");

    out.println("<tr><td>");
    out.println("Time envelope:</td><td><input name=\"timeEnvelope\" type=\"text\" value=\"\"></td>");
    out.println("<td><i>The default time envelope for a certificate to be valid.<br>");
    out.println("The certificate will be valid between this period to the actual time<br>");
    out.println("it is approved by CA, plus the validity period above after its approval.<br>");
    out.println("Format:    <b>a1 y a2 M a3 d a4 h a5 m a6 s</b> ");
    out.println("where a1...a6 is a number<br>");
    out.println("y=year, M=month, d=day, h=hour, m=minute, s=second. At least one key is required<br>");
    out.println("</i></td>");

    out.println("<tr><td>");
    out.println("Key size:</td><td><input name=\"KeySize\" type=\"text\" value=\"\"></td>");
    out.println("<td><i></i></td>");
    out.println("</tr>");

    out.println("<tr><td>");
    out.println("Require pending:</td><td><input name=\"RequirePending\" type=\"text\" value=\"\"></td>");
    out.println("<td><i>true: the administrator must manually sign the certificates.<br>");
    out.println("false: Certificates are signed automatically.");
    out.println("WARNING: \"false\" should be used for test purposes only");
    out.println("</i></td>");

    out.println("<tr><td>");
    out.println("Node is signer:</td><td><input name=\"nodeIsSigner\" type=\"text\" value=\"true\"></td>");
    out.println("<td><i>true: the administrator allows node to sign agent certificates.<br>");
    out.println("false: Agent certificates are signed by the CA.");
    out.println("</i></td>");

    out.println("<br></tr><br>");

    out.println("<br><input type=\"submit\">&nbsp;&nbsp;&nbsp;");
    out.println("<input type=\"reset\">");
    out.println("</form></table>");

    // Help on client configuration
    out.println("<br><b>Client Configuration help</b><br>");
    out.println("Every client using this CA should be configured with:<br>");
    out.println("* The LDAP URL as specified above to retrieve certificates<br>");
    String uri = req.getRequestURI();
    String path = uri.substring(0, uri.lastIndexOf('/'));
    String certpath = path + "/CertificateSigningRequest";

    out.println("* The " + certpath + " URL to request certificates<br>");
    out.println("* The public key of this CA in their trusted CA keystore<br>");

    out.println("</body></html>");
    out.flush();
    out.close();
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {
    String param = req.getParameter("param");
    if (param == null) {
      doCaForm(req, res);
    }
  }

  public String getServletInfo()  {
    return("Generate a CA key");
  }

}
