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

import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.w3c.dom.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import java.io.*;
import java.util.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import java.lang.reflect.Array;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.util.*;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

public class ConfigParserHandler
  extends BaseConfigHandler
{
  // Handler delegates
  private CryptoClientPolicyHandler cryptoClientHandler;
  private ServletPolicyHandler servletHandler;
  private BlackboardFilterPolicyHandler bbFilterHandler;
  private LdapUserServicePolicyHandler userdbHandler;
  private CaPolicyHandler caPolicyHandler;
  private CryptoPolicyHandler cryptoPolicyHandler;
  private CryptoPolicyHandler dpPolicyHandler;
  private MsgAccessPolicyHandler msgAccessPolicyHandler;
  private ServiceBroker serviceBroker;
  private LoggingService log;
  /** The name of the community of type SecurityCommunity. */
  private String mySecurityCommunity;

  /** A Vector of SecurityPolicy
   */
  private ArrayList securityPolicies;

  private static final String POLICY_ELEMENT = "policy";

  // name of the crypto client policy file for this node.  should be of the form
  // $COUGAAR_WORKSPACE/security/keystores/${org.cougaar.node.name}/cryptoPolicy.xml
  private String cryptoPolicyFileName;

  // Constructor with XML Parser...
  ConfigParserHandler(XMLReader parser, String role,
		      ServiceBroker sb, String community) {
    super(sb);
    this.parser = parser;
    this.role = role;
    this.serviceBroker = sb;
    this.mySecurityCommunity = community;
    this.log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    cryptoClientHandler = new CryptoClientPolicyHandler(serviceBroker);
    cryptoClientHandler.setRole(role);
    cryptoClientHandler.setSecurityCommunity(mySecurityCommunity);

    servletHandler = new ServletPolicyHandler(serviceBroker);
    servletHandler.setRole(role);
    servletHandler.setSecurityCommunity(mySecurityCommunity);

    bbFilterHandler = new BlackboardFilterPolicyHandler(serviceBroker);
    bbFilterHandler.setRole(role);
    bbFilterHandler.setSecurityCommunity(mySecurityCommunity);

    userdbHandler = new LdapUserServicePolicyHandler(serviceBroker);
    userdbHandler.setRole(role);
    userdbHandler.setSecurityCommunity(mySecurityCommunity);

    caPolicyHandler = new CaPolicyHandler(serviceBroker);
    caPolicyHandler.setRole(role);
    caPolicyHandler.setSecurityCommunity(mySecurityCommunity);

    cryptoPolicyHandler = new CryptoPolicyHandler(serviceBroker);
    cryptoPolicyHandler.setRole(role);
    cryptoPolicyHandler.setSecurityCommunity(mySecurityCommunity);
    dpPolicyHandler = new CryptoPolicyHandler(serviceBroker);

    msgAccessPolicyHandler = new MsgAccessPolicyHandler(serviceBroker);
    msgAccessPolicyHandler.setRole(role);
    msgAccessPolicyHandler.setSecurityCommunity(mySecurityCommunity);

    securityPolicies = new ArrayList();
    // construct the crypto client policy file name.  should be of the form
    // $COUGAAR_WORKSPACE/security/keystores/${org.cougaar.node.name}/cryptoPolicy.xml
    SecurityPropertiesService sps = (SecurityPropertiesService)
      sb.getService(this, SecurityPropertiesService.class, null);
    String nodeName = sps.getProperty("org.cougaar.node.name");
    String cougaarWsp = sps.getProperty(sps.COUGAAR_WORKSPACE);
    String topDirectory = cougaarWsp + File.separatorChar + "security"
      + File.separatorChar + "keystores" + File.separatorChar;
    String nodeDirectory = topDirectory + nodeName;
    cryptoPolicyFileName = nodeDirectory + File.separatorChar + "cryptoPolicy.xml";
    sb.releaseService(this, SecurityPropertiesService.class, sps);
  }

  public SecurityPolicy[] getSecurityPolicies() {
    SecurityPolicy[] ccp = new SecurityPolicy[securityPolicies.size()];
    securityPolicies.toArray(ccp);
    return ccp;
  }

  public SecurityPolicy[] getSecurityPolicies(Class policyClass) {
    Iterator it = securityPolicies.iterator();
    ArrayList al = new ArrayList();
    while (it.hasNext()) {
      Object o = it.next();
      if (o.getClass().equals(policyClass)) {
	al.add(o);
      }
    }
    int size = al.size();

    if (log.isDebugEnabled()) {
      log.debug("Requesting policy of type " + policyClass.getName()
		+ " Returning " + size + " policy objects");
    }

    SecurityPolicy[] array =
      (SecurityPolicy[])al.toArray(new SecurityPolicy[size]);
    return array;
  }

  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr )
    throws SAXException {
    super.startElement(namespaceURI, localName, qName, attr);
    if (log.isDebugEnabled()) {
      log.debug("ConfigParserHandler: " + localName);
    }

    if (localName.equalsIgnoreCase(POLICY_ELEMENT)) {
      String policyType = attr.getValue("type");
      if (log.isDebugEnabled()) {
	log.debug("ConfigParserHandler: policyType=" + policyType);
      }
      if (policyType == null) {
	return;
      }
      else if (policyType.equals("cryptoClientPolicy")) {
	cryptoClientHandler.collectPolicy(parser, this, POLICY_ELEMENT);
	SecurityPolicy newSecPolicy = cryptoClientHandler.getSecurityPolicy();
	newSecPolicy.setName(attr.getValue("name"));
	securityPolicies.add(newSecPolicy);
      }
      else if (policyType.equals("certificateAuthorityPolicy")) {
	caPolicyHandler.collectPolicy(parser, this, POLICY_ELEMENT);
	SecurityPolicy newSecPolicy = caPolicyHandler.getSecurityPolicy();
	newSecPolicy.setName(attr.getValue("name"));
	securityPolicies.add(newSecPolicy);
      }
      else if (policyType.equals("org.cougaar.core.security.policy.CryptoPolicy")) {
	cryptoPolicyHandler.collectPolicy(parser, this, POLICY_ELEMENT);
	SecurityPolicy newSecPolicy = cryptoPolicyHandler.getSecurityPolicy();
	newSecPolicy.setName(attr.getValue("name"));
	securityPolicies.add(newSecPolicy);
      }
      else if (policyType.equals("org.cougaar.core.security.policy.DataProtectionPolicy")) {
	dpPolicyHandler.collectPolicy(parser, this, POLICY_ELEMENT);
	DataProtectionPolicy newSecPolicy = new DataProtectionPolicy();
        newSecPolicy.setCryptoPolicy((CryptoPolicy)dpPolicyHandler.getSecurityPolicy());
	newSecPolicy.setName(attr.getValue("name"));
	securityPolicies.add(newSecPolicy);
      }
      else if (policyType.equals("org.cougaar.core.security.policy.AccessControlPolicy")) {
	msgAccessPolicyHandler.collectPolicy(parser, this, POLICY_ELEMENT);
	SecurityPolicy newSecPolicy = msgAccessPolicyHandler.getSecurityPolicy();
	newSecPolicy.setName(attr.getValue("name"));
	securityPolicies.add(newSecPolicy);
      }
      else if (policyType.equals("org.cougaar.core.security.policy.ServletPolicy")) {
	servletHandler.collectPolicy(parser, this, POLICY_ELEMENT);
	SecurityPolicy newSecPolicy = servletHandler.getSecurityPolicy();
	newSecPolicy.setName(attr.getValue("name"));
	securityPolicies.add(newSecPolicy);
      }
      else if (policyType.equals("org.cougaar.core.security.policy.BlackboardFilterPolicy")) {
	bbFilterHandler.collectPolicy(parser, this, POLICY_ELEMENT);
	SecurityPolicy newSecPolicy = bbFilterHandler.getSecurityPolicy();
	newSecPolicy.setName(attr.getValue("name"));
	securityPolicies.add(newSecPolicy);
      }
      else if (policyType.equals("org.cougaar.core.security.policy.LdapUserServicePolicy")) {
	userdbHandler.collectPolicy(parser, this, POLICY_ELEMENT);
	SecurityPolicy newSecPolicy = userdbHandler.getSecurityPolicy();
	newSecPolicy.setName(attr.getValue("name"));
	securityPolicies.add(newSecPolicy);
      } else {
	if (log.isWarnEnabled()) {
	  log.warn("Cannot find handler for policy type: " + policyType);
	}
      }
    }
  }

  public void endElement( String namespaceURI,
			  String localName,
			  String qName )
    throws SAXException {
  }

  public String toString() {
    String s = "";
    SecurityPolicy[] securityPolicies = getSecurityPolicies();
    for (int i = 0 ; i < securityPolicies.length ; i++) {
      s = s + "Policy[" + i + "] - " + securityPolicies[i].getClass().getName()
	+ " :\n";
      s = s + securityPolicies[i].toString() + "\n";
    }
    return s;
  }

  public void addSecurityPolicy(SecurityPolicy policy) {
    securityPolicies.add(policy);
  }
  
  // package level access
  void updateSecurityPolicy(SecurityPolicy policy) 
    throws PolicyUpdateException {
    if(policy == null) {
      throw new PolicyUpdateException("no security policy specified");
    }
    if(policy instanceof CryptoClientPolicy) {
      CryptoClientPolicy ccp = (CryptoClientPolicy)policy;
      saveCryptoClientPolicy(ccp);
    }
    else {
      throw new
        PolicyUpdateException(policy.getName() + " updates not supported.");
    }
  }
  
  private void saveCryptoClientPolicy(CryptoClientPolicy policy) 
    throws PolicyUpdateException {
    File policyFile = new File(cryptoPolicyFileName);
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document updatedPolicy = builder.newDocument(); // the xml file to write
      Element root = updatedPolicy.createElement("policies");
      Element policyNode = updatedPolicy.createElement(POLICY_ELEMENT);
      // crypto client policy
      policyNode.setAttribute("name", policy.getName());
      policyNode.setAttribute("type", "cryptoClientPolicy");
      policyNode.appendChild(policy.convertToXML(updatedPolicy));
      root.appendChild(policyNode);
      // end crypto client policy
      // ca policy
      if(policy.isCertificateAuthority()) {
        SecurityPolicy[] caPolicies = getSecurityPolicies(CaPolicy.class);
        // assuming only one ca policy per node
        CaPolicy caPolicy = (CaPolicy)caPolicies[0];
        policyNode = updatedPolicy.createElement(POLICY_ELEMENT);
        policyNode.setAttribute("name", caPolicy.getName());
        policyNode.setAttribute("type", "certificateAuthorityPolicy");
        policyNode.appendChild(caPolicy.convertToXML(updatedPolicy));
        root.appendChild(policyNode);
      }
      // end ca policy
      updatedPolicy.appendChild(root);
      // well just write over the previous cryptoPolicy.xml file
      FileOutputStream fos = new FileOutputStream(policyFile);
      OutputFormat of = new OutputFormat(updatedPolicy, "US-ASCII", true);
      // no line wrapping
      of.setLineWidth(0);
      // indent 2 spaces
      of.setIndent(2);
      XMLSerializer xs = new XMLSerializer(fos, of);
      xs.serialize(updatedPolicy);
      fos.flush();
      fos.close();
    }
    catch(Exception e) {
      throw new PolicyUpdateException(e);
    }
    log.debug("Saved crypto client policy " + cryptoPolicyFileName);
  }
}
