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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.ConfigFinder;
import org.cougaar.util.jar.JarConfigFinder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

import sun.security.x509.X500Name;

/** Helper class to read the cryptographic service configuration.
 *
 */
public class ConfigParserServiceImpl
  implements ConfigParserService
{
  private SecurityPropertiesService secprop = null;
  private ConfigFinder confFinder;
  //private boolean isCertAuthority = false;
  private String role;
  private ServiceBroker serviceBroker;
  private LoggingService log;
  /** The name of the community of type SecurityCommunity. */
  private String mySecurityCommunity;

  // XML Parser
  private XMLReader parser;
  private ConfigParserHandler handler;

  // Are we executing within a node or as a standalone application?
  private boolean isNode;

  public ConfigParserServiceImpl(ServiceBroker sb, String community) {
    serviceBroker = sb;
    mySecurityCommunity = community;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class,
			       null);

    isNode =
      Boolean.valueOf(System.getProperty("org.cougaar.core.security.isExecutedWithinNode")).booleanValue();
    // Add workspace/security/keystores/$nodeName directory to the search path
    String nodeName = secprop.getProperty("org.cougaar.node.name");
    if (nodeName == null || nodeName.length() == 0) {
      if (isNode) {
	// The node name property should always be set when running as a Cougaar node.
	log.error("org.cougaar.node.name property has not been set");
      }
      else {
	// When running a standalone application, it is ok not to have the workspace property set,
	// but then SSL is not possible.
	log.warn("org.cougaar.node.name property has not been set. Cannot use SSL");
      }
    }

    String cougaarWsp=secprop.getProperty(secprop.COUGAAR_WORKSPACE);
    log.debug("Cougaar workspace is :" + cougaarWsp);
    if (cougaarWsp == null || cougaarWsp.length() == 0) {
      if (isNode) {
	// The org.cougaar.workspace property should always be set when running as a Cougaar node.
	log.error(secprop.COUGAAR_WORKSPACE + " property has not been set");
      }
      else {
	// When running a standalone application, it is ok not to have the workspace property set,
	// but then SSL is not possible.
	log.warn(secprop.COUGAAR_WORKSPACE + " property has not been set. Cannot use SSL");
      }
    }

    String topDirectory = cougaarWsp + File.separatorChar + "security"
      + File.separatorChar + "keystores" + File.separatorChar;
    String nodeDirectory = topDirectory + nodeName;

    String searchPath = nodeDirectory + ";"
      + System.getProperty("org.cougaar.config.path");
    log.debug("Search path is set to: " + searchPath);
    confFinder = new JarConfigFinder(searchPath);

    try {
      // Create SAX 2 parser...
      parser = XMLReaderFactory.createXMLReader("org.apache.xerces.parsers.SAXParser");
    }
    catch ( Exception e ) {
      e.printStackTrace();
    }
    role = secprop.getProperty(secprop.SECURITY_ROLE);

    // Set the ContentHandler...
    handler = new ConfigParserHandler(parser, role, serviceBroker, mySecurityCommunity);
    parser.setContentHandler(handler);
/*
    setConfigurationFile("cryptoPolicy.xml");
    setConfigurationFile("BootPolicy.MsgAccess.xml");
    setConfigurationFile("BootPolicy.Servlet.xml");
    setConfigurationFile("BootPolicy.UserDB.xml");
    setConfigurationFile("BootPolicy.BBFilter.xml");
    setConfigurationFile("BootPolicy.DataProtection.xml");
    setConfigurationFile("BootPolicy.Crypto.xml");
 */
    processBootPolicyFiles("BootPolicyList.ini");
  }

  //read in boot policy file list
  private void processBootPolicyFiles(String filename){

    InputStream is = null;
    try {
      is = confFinder.open(filename);
    }
    catch (IOException e) {
      log.fatal("Unable to open policy file:" + e);
    }
    if (is == null) {
      if (isNode) {
	log.fatal("Unable to get list of policy files. Install the BootPolicyList.ini file");
      }
      else {
	log.warn("Unable to get list of policy files. Cannot use SSL");
      }
      throw new
	RuntimeException("Unable to get list of policy files. Install the BootPolicyList.ini file");
    }
    try {
      BufferedReader buffreader=new BufferedReader(new InputStreamReader(is));
      String linedata=new String();

      while((linedata=buffreader.readLine())!=null) {
        linedata.trim();
        if(linedata.startsWith("#")) {
          continue;
        }
        //not empty line
        if(linedata.length() > 1) setConfigurationFile(linedata);
      }
      buffreader.close();
    }
    catch(FileNotFoundException fnotfoundexp) {
      if (log.isErrorEnabled()) {
        log.error("Unable to find boot policy configuration file " + fnotfoundexp);
        fnotfoundexp.printStackTrace();
      }
    }
    catch(IOException ioexp) {
      if (log.isErrorEnabled()) {
        log.error("Unable to read boot policy configuration file " + ioexp);
        ioexp.printStackTrace();
      }
    }

  }

  /** Find a boot policy file
   *  First, search in the workspace.
   *  Second, search using ConfigFinder.
   */
  public InputStream findPolicyFile(String policyfilename) {

    // Search using the config finder.
    InputStream is = null;
    URL aURL = null;
    try {
      is = confFinder.open(policyfilename);
      aURL = confFinder.find(policyfilename);
    }
    catch (IOException e) {
      log.fatal("Unable to open policy file:" + e);
    }

    if (is == null) {
      if (log.isErrorEnabled()) {
	// Cannot proceed without policy
	log.error("Cannot continue secure execution without policy");
	log.error("Could not find configuration file: "
		  + policyfilename);
      }
      throw new RuntimeException("No policy available");
    }
    if(log.isDebugEnabled()) {
      log.debug("Policy file:" + aURL);
    }
    return is;
  }

  private void setConfigurationFile(String defaultFile) {
    InputStream policyIs = findPolicyFile(defaultFile);
    parsePolicy(policyIs);
    if (policyIs != null) {
      try {
	policyIs.close();
      }
      catch (IOException e) {
	if (log.isWarnEnabled()) {
	  log.warn("Unable to close stream: " + defaultFile);
	}
      }
    }
  }
  
  /*
  public Document getConfigDocument() {
    return configDoc;
  }
  */

  public CaPolicy getCaPolicy(String aDN) {
    if (log.isDebugEnabled()) {
      log.debug("Requesting CA policy for " + aDN);
    }
    if (aDN == null) {
      log.error("CA distinguished name is null", new Throwable());
      return null;
    }
    try {
      SecurityPolicy[] policy = getSecurityPolicies(CaPolicy.class);
      X500Name x500Name = null;
      x500Name = new X500Name(aDN);

      for (int i = 0 ; i < policy.length ; i++) {
	if (log.isDebugEnabled()) {
	  log.debug("Current policy: " + policy[i]);
	}

	/**
	 * a fix for the node ca policy
	 */
	if (aDN.length() == 0 && ((CaPolicy)policy[i]).caDnName == null)
	  return (CaPolicy)policy[i];

	if (x500Name.equals(((CaPolicy)policy[i]).caDnName)) {
	  return (CaPolicy)policy[i];
	}
      }
    }
    catch (Exception e) {
      if (log.isErrorEnabled()) {
	log.error("Unable to get CA policy: " + e.toString());
	e.printStackTrace();
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
    catch (Exception e) {
      // This is OK for standalone applications, but not for nodes.
      if (isNode == true) {
	log.warn("Unable to parse policy. Reason:" + e);
      }
      else {
	log.debug("Unable to parse policy. Reason:" + e);
      }
    }
  }

  public SecurityPolicy[] getSecurityPolicies() {
    return handler.getSecurityPolicies();
  }

  public SecurityPolicy[] getSecurityPolicies(Class policyClass) {
    return handler.getSecurityPolicies(policyClass);
  }

  public void updateSecurityPolicy(SecurityPolicy policy) 
    throws PolicyUpdateException {
    handler.updateSecurityPolicy(policy);
  }

  public boolean isCertificateAuthority() {
    SecurityPolicy[] secPol = getSecurityPolicies(CryptoClientPolicy.class);
    if (secPol.length != 1) {
      throw new RuntimeException("Inconsistent policy. Got "
				 + secPol.length + " crypto client policies");
    }
    CryptoClientPolicy ccp = (CryptoClientPolicy) secPol[0];
    return ccp.isCertificateAuthority();
  }

  public X500Name[] getCaDNs()
  {
    X500Name[] caDNs = new X500Name[0];
    ArrayList caList = new ArrayList();
    SecurityPolicy[] policy = getSecurityPolicies(CaPolicy.class);

    for (int i = 0 ; i < policy.length ; i++) {
      caList.add(((CaPolicy)policy[i]).caDnName);
    }
    caDNs = (X500Name[]) caList.toArray(caDNs);
    return caDNs;
  }

  /** Retrieve all the roles */
  public String[] getRoles()
  {
    HashSet roleSet = new HashSet();
    String[] roles = new String[0];
    Document configDoc = null;
    try {
      configDoc = confFinder.parseXMLConfigFile("cryptoPolicy.xml");
    }
    catch (Exception e) {
      log.warn("Unable to get roles from policy file:" + e);
    }
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

  public void addSecurityPolicy(SecurityPolicy policy) {
    handler.addSecurityPolicy(policy);
  }
}
