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

// Cougaar Security Services
import com.nai.security.policy.*;
import com.nai.security.util.*;
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

  // XML Parser
  private XMLReader parser;
  private ConfigParserHandler handler;

  public ConfigParserServiceImpl() {
    confFinder = new ConfigFinder();
    // TODO. Modify following line to use service broker instead
    secprop = SecurityServiceProvider.getSecurityProperties(null);
    try {
      // Create SAX 2 parser...
      parser = XMLReaderFactory.createXMLReader("org.apache.xerces.parsers.SAXParser");
    }
    catch ( Exception e ) {
      e.printStackTrace();
    }
    role = secprop.getProperty(secprop.SECURITY_ROLE); 

    // Set the ContentHandler...
    handler = new ConfigParserHandler(parser, role);
    parser.setContentHandler(handler);

    setConfigurationFile();
  }

  public File findWorkspacePolicyPath(String policyfilename) {
    String nodeName = secprop.getProperty("org.cougaar.node.name");

    String cougaarWsp=secprop.getProperty(secprop.COUGAAR_WORKSPACE);
    System.out.println("Cougaar workspace is :" + cougaarWsp);

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
    String configFile = secprop.getProperty(secprop.CRYPTO_CONFIG,
				     policyfilename);

    // 1) Search using the workspace
    f = findWorkspacePolicyPath(configFile);

    if (!f.exists()) {
      // 2) Search using the config finder.

      f = confFinder.locateFile(configFile);
    
      if (f == null) {
	if (CryptoDebug.debug) {
	  System.out.println("Unable to read configFile: " + configFile);
	}
	// Cannot proceed without policy
	System.err.println("ERROR: Cannot continue secure execution without policy");
	System.err.println("ERROR: Could not find crypto configuration file: " + configFile);
	try {
	  throw new RuntimeException("No policy available");
	}
	catch (RuntimeException ex) {
	  ex.printStackTrace();
	}
	System.exit(-1);
      }
    }
    if(CryptoDebug.debug) {
      System.out.println("Policy file:" + f.getPath());
    }
    return f;
  }

  private void setConfigurationFile() {
    String configPath = null;
    String defaultFile = "cryptoPolicy.xml";
    configPath = findPolicyFile(defaultFile).getPath();

    try {
      configDoc = confFinder.parseXMLConfigFile(configPath);
      FileInputStream fis = new FileInputStream(configPath);
      parsePolicy(fis);
    }
    catch (IOException e) {
      if (CryptoDebug.debug) {
	System.out.println("Unable to read configFile: " + e);
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
    CaPolicy[] policy =
      (CaPolicy[])getSecurityPolicies(CaPolicy.class);

    X500Name x500Name = null;
    if (CryptoDebug.debug) {
      System.out.println("Requesting CA policy for " + aDN);
    }
    try {
      x500Name = new X500Name(aDN);
    }
    catch (IOException e) {
      if (CryptoDebug.debug) {
	System.out.println("Unable to parse DN");
      }
      return null;
    }

    for (int i = 0 ; i < policy.length ; i++) {
      if (CryptoDebug.debug) {
	System.out.println("Current policy: " + policy[i].caDnName.toString());
      }
      if (x500Name.equals(policy[i].caDnName)) {
	return policy[i];
      }
    }
    return null;
  }

  public void parsePolicy(InputStream policy) {
    if (CryptoDebug.debug) {
      System.out.println("Reading policy object");
    }
    try {
      // Parse the file...
      parser.parse(new InputSource(policy));

      if (CryptoDebug.debug) {
	System.out.println(handler.toString());
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
