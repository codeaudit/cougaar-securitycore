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

import org.xml.sax.*;
import org.xml.sax.helpers.*;
import java.io.*;
import java.util.*;
import java.lang.reflect.Array;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.util.*;

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
}
