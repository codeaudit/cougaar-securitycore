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

package org.cougaar.core.security.config;

import java.security.cert.*;
import java.security.KeyStore;
import java.util.*;
import java.net.*;
import java.io.*;
import java.lang.reflect.*;

import org.xml.sax.*;
import org.xml.sax.helpers.*;

import org.w3c.dom.*;
import org.cougaar.util.*;

import sun.security.x509.*;
import sun.security.util.ObjectIdentifier;

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

// Cougaar Security Services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.util.*;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.provider.SecurityServiceProvider;

/** Helper class to read the cryptographic service configuration.
 *
 */
public class ConfigParserServiceImpl
  implements ConfigParserService
{
  private SecurityPropertiesService secprop = null;
  private ConfigFinder confFinder;
  private boolean isCertAuthority = false;
  private Document configDoc = null;
  private String role;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  // XML Parser
  private XMLReader parser;
  private ConfigParserHandler handler;

  public ConfigParserServiceImpl(ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class,
			       null);
    confFinder = new ConfigFinder();

    try {
      // Create SAX 2 parser...
      parser = XMLReaderFactory.createXMLReader("org.apache.xerces.parsers.SAXParser");
    }
    catch ( Exception e ) {
      e.printStackTrace();
    }
    role = secprop.getProperty(secprop.SECURITY_ROLE);

    // Set the ContentHandler...
    handler = new ConfigParserHandler(parser, role, serviceBroker);
    parser.setContentHandler(handler);

    setConfigurationFile("cryptoPolicy.xml");
    setConfigurationFile("BootPolicy.Crypto.xml");
    setConfigurationFile("BootPolicy.MsgAccess.xml");
  }

  public File findWorkspacePolicyPath(String policyfilename) {
    String nodeName = secprop.getProperty("org.cougaar.node.name");

    String cougaarWsp=secprop.getProperty(secprop.COUGAAR_WORKSPACE);
    log.debug("Cougaar workspace is :" + cougaarWsp);

    String topDirectory = cougaarWsp + File.separatorChar + "security"
      + File.separatorChar + "keystores" + File.separatorChar;

    String nodeDirectory = topDirectory + nodeName + File.separatorChar;

    String configFile = nodeDirectory + policyfilename;

    return new File(configFile);
  }

  /** Find a boot policy file
   *  First, search in the workspace.
   *  Second, search using ConfigFinder.
   */
  public File findPolicyFile(String policyfilename) {
    File f = null;

    // 1) Search using the workspace
    f = findWorkspacePolicyPath(policyfilename);

    if (!f.exists()) {
      // 2) Search using the config finder.

      f = confFinder.locateFile(policyfilename);

      if (f == null) {
	if (log.isErrorEnabled()) {
	  // Cannot proceed without policy
	  log.error("Cannot continue secure execution without policy");
	  log.error("Could not find configuration file: "
		    + policyfilename);
	}
	throw new RuntimeException("No policy available");
      }
    }
    if(log.isDebugEnabled()) {
      log.debug("Policy file:" + f.getPath());
    }
    return f;
  }

  private void setConfigurationFile(String defaultFile) {
    try {
      String configPath = null;
      configPath = findPolicyFile(defaultFile).getPath();

      configDoc = confFinder.parseXMLConfigFile(defaultFile);
      FileInputStream fis = new FileInputStream(configPath);
      parsePolicy(fis);
    }
    catch (IOException e) {
      if (log.isErrorEnabled()) {
	log.error("Unable to read configFile: " + e);
	e.printStackTrace();
      }
    }
  }

  public Document getConfigDocument() {
    return configDoc;
  }

  public CryptoClientPolicy getCryptoClientPolicy() {
    CryptoClientPolicy[] policy =
      (CryptoClientPolicy[])getSecurityPolicies(CryptoClientPolicy.class);

    if (policy.length != 1) {
      throw new RuntimeException("Inconsistent policy. Got "
				 + policy.length + " crypto client policies");
    }
    return policy[0];
  }

  public CaPolicy getCaPolicy(String aDN) {
    if (log.isDebugEnabled()) {
      log.debug("Requesting CA policy for " + aDN);
    }

    CaPolicy[] policy =
      (CaPolicy[])getSecurityPolicies(CaPolicy.class);

    X500Name x500Name = null;
    try {
      x500Name = new X500Name(aDN);
    }
    catch (IOException e) {
      if (log.isErrorEnabled()) {
	log.error("Unable to parse DN: " + aDN);
      }
      return null;
    }

    for (int i = 0 ; i < policy.length ; i++) {
      if (log.isDebugEnabled()) {
	log.debug("Current policy: " + policy[i]);
      }

      /**
       * a fix for the node ca policy
       */
      if (aDN.length() == 0 && policy[i].caDnName == null)
        return policy[i];

      if (x500Name.equals(policy[i].caDnName)) {
	return policy[i];
      }
    }
    return null;
  }

  public void parsePolicy(InputStream policy) {
    if (log.isDebugEnabled()) {
      log.debug("Reading policy object");
    }
    try {
      // Parse the file...
      parser.parse(new InputSource(policy));

      if (log.isDebugEnabled()) {
	log.debug(handler.toString());
      }
    }
    catch ( Exception e ) {
      e.printStackTrace();
    }
  }

  public SecurityPolicy[] getSecurityPolicies() {
    return handler.getSecurityPolicies();
  }

  public SecurityPolicy[] getSecurityPolicies(Class policyClass) {
    return handler.getSecurityPolicies(policyClass);
  }

  public boolean isCertificateAuthority() {
    return getCryptoClientPolicy().isCertificateAuthority();
  }

  public X500Name[] getCaDNs()
  {
    X500Name[] caDNs = new X500Name[0];
    ArrayList caList = new ArrayList();
    CaPolicy[] policy = (CaPolicy[])getSecurityPolicies(CaPolicy.class);

    for (int i = 0 ; i < policy.length ; i++) {
      caList.add(policy[i].caDnName);
    }
    caDNs = (X500Name[]) caList.toArray(caDNs);
    return caDNs;
  }

  /** Retrieve all the roles */
  public String[] getRoles()
  {
    HashSet roleSet = new HashSet();
    String[] roles = new String[0];

    addRole(configDoc.getDocumentElement(), roleSet);
    return (String[]) roleSet.toArray(roles);
  }

  private void addRole(Element e, HashSet set)
  {
    if (e == null) {
      return;
    }
    NodeList list = e.getChildNodes();
    for (int i = 0 ; i < list.getLength() ; i++) {
      Node aNode = list.item(i);
      if (aNode.getNodeType() != org.w3c.dom.Node.ELEMENT_NODE) {
	continue;
      }
      Element element = (Element) aNode;
      addRole(element, set);
      String aRole = element.getAttribute("role");
      if (aRole != null) {
	set.add(aRole);
      }
    }
  }
}
