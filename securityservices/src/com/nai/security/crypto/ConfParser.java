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

package com.nai.security.crypto;

import java.security.cert.*;
import java.security.KeyStore;
import java.util.*;
import java.net.*;
import java.io.*;
import java.lang.reflect.*;

import org.w3c.dom.*;
import org.cougaar.util.*;

import sun.security.x509.*;
import sun.security.util.ObjectIdentifier;

import com.nai.security.policy.*;
import com.nai.security.util.*;

/** Helper class to read the cryptographic service configuration.
 * 
 */
public class ConfParser {

  boolean standalone = false;

  private String configFile = null;
  private Document configDoc = null;

  public ConfParser(boolean isStandalone) {
    String defaultConfigFile = "cryptoPolicy.xml";

    configFile = System.getProperty("org.cougaar.security.crypto.config",
				    defaultConfigFile);
    System.out.println("conf file is at :"+configFile);
    standalone = isStandalone;
    init();
  }
   public ConfParser(String path, boolean isStandalone) {
     if(path==null) {
       if(CryptoDebug.debug) {
	 System.out.println(" Got conf path as: null:");
       }
       String defaultConfigFile= "cryptoPolicy.xml";
       configFile=defaultConfigFile;
     }
     else {
       configFile=path;
     }
     standalone = isStandalone;
     init();
  }

  public Document getConfigDocument() {
    return configDoc;
  }

  public void init( ) {
    
    ConfigFinder confFinder = new ConfigFinder();
    try {
      configDoc = confFinder.parseXMLConfigFile(configFile);
    }
    catch (IOException e) {
      if (CryptoDebug.debug) {
	System.out.println("Unable to read configFile: " + e);
	e.printStackTrace();
      }
    }
    if (configDoc == null) {
      
      // Cannot proceed without policy
      System.err.println("ERROR: Cannot continue secure execution without policy");
      System.err.println("ERROR: Could not find crypto configuration file: " + configFile);
      try {
	throw new RuntimeException("No policy available");
      }
      catch (RuntimeException e) {
	e.printStackTrace();
      }
      System.exit(-1);
    }
  }

  public NodeList getChildren(String elementName) {
    NodeList children =
      configDoc.getDocumentElement().getElementsByTagName(elementName);
    return children;
  }

  // Node policy
  public static final String NODE_POLICY_ELEMENT       = "nodeConfiguration";
  public static final String NODE_CA_DN_ELEMENT        = "CA_DN";
  public static final String NODE_CA_URL_ELEMENT       = "CA_URL";
  public static final String NODE_OU_ELEMENT           = "ou";
  public static final String NODE_O_ELEMENT            = "o";
  public static final String NODE_L_ELEMENT            = "l";
  public static final String NODE_ST_ELEMENT           = "st";
  public static final String NODE_C_ELEMENT            = "c";
  public static final String NODE_KEYALGNAME_ELEMENT   = "keyAlgName";
  public static final String NODE_SIGALGNAME_ELEMENT   = "sigAlgName";
  public static final String NODE_KEYSIZE_ELEMENT      = "keysize";
  public static final String NODE_VALIDITY_ELEMENT     = "validity";
  public static final String NODE_CA_KEYSTORE_ELEMENT  = "CA_keystore";
  public static final String NODE_CA_KEYSTORE_PWD_ELEMENT  = "CA_keystorePassword";

  public static final String NODE_CERTDIRURL_ELEMENT   = "CertDirectoryURL";
  public static final String NODE_CERTDIRTYPE_ELEMENT = "CertDirectoryType";

  // CA policy
  public static final String CA_POLICY_ELEMENT         = "certificateAuthority";
  public static final String CA_KEYSTORE_ELEMENT       = "keystoreFile";
  public static final String CA_KEYSTORE_PWD_ELEMENT   = "keystorePassword";
  public static final String CA_CN_ELEMENT             = "caCommonName";
  public static final String CA_LDAP_URL_ELEMENT       = "ldapURL";
  public static final String CA_LDAP_TYPE_ELEMENT      = "ldapType";
  public static final String CA_SERIAL_NB_FILE_ELEMENT = "serialNumberFile";
  public static final String CA_PKCS10_DIR_ELEMENT     = "pkcs10Directory";
  public static final String CA_X509_CERT_DIR_ELEMENT  = "x509CertDirectory";
  public static final String CA_CERT_PENDING_DIR_ELEMENT  = "CertPendingDirectory";
  public static final String CA_CERT_DENIED_DIR_ELEMENT  = "CertDeniedDirectory";

  public static final String CA_CLIENT_POLICY_ELEMENT  = "clientCertPolicy";

  public static final String CA_CERTVERSION_ELEMENT    = "certVersion";
  public static final String CA_ALGORITHMID_ELEMENT    = "algorithmId";
  public static final String CA_CRL_ALGORITHMID_ELEMENT= "crlalgorithmId";
  public static final String CA_KEYSIZE_ELEMENT        = "keysize";
  public static final String CA_CERTVALIDITY_ELEMENT   = "certValidity";
  public static final String CA_REQUIREPENDING_ELEMENT   = "requirePending";

  public void iterate(String name) {
    NodeList conf = configDoc.getDocumentElement().getElementsByTagName(name);
    for (int i = 0 ; i < conf.getLength() ; i++) {
      Node o = conf.item(i);
    }
  }

  private void printTree(Node e, int level) {
    for (int i = 0 ; i < level ; i++) {
      System.out.print("  ");
    }
    System.out.println("Node: " + e.getNodeName()
		       + " Type: " + e.getNodeType()
		       + " Val: " + e.getNodeValue()
		       );
    NodeList nodes = e.getChildNodes();
    if (nodes == null) {
      return;
    }
    for (int j = 0 ; j < nodes.getLength() ; j++) {
      printTree(nodes.item(j), level + 1);
    }
  }

  /** This returns the first child element within this element
      with the given local name and belonging to no namespace. */
  private Element getChild(Element e, String tagName)
  {
    NodeList nodes = e.getElementsByTagName(tagName);
    if (nodes == null) {
      if (CryptoDebug.debug) {
	System.out.println("No such tag: " + tagName);
      }
      return null;
    }
    for (int i = 0 ; i < nodes.getLength() ; i++) {
      if (nodes.item(i).getNodeType() == org.w3c.dom.Node.ELEMENT_NODE) {
	return (Element) nodes.item(i);
      }
    }
    return null;
  }

  public NodePolicy readNodePolicy(String role)
    throws NoSuchFieldException, IllegalAccessException
  {
    if (CryptoDebug.debug) {
      System.out.println("Reading node policy");
    }
    Element nodePolicyElement = getChild(configDoc.getDocumentElement(),
					 NODE_POLICY_ELEMENT);

    NodePolicy nodePolicy = new NodePolicy();

    nodePolicy.CA_DN =
      getElementValue(nodePolicyElement,
		      NODE_CA_DN_ELEMENT, role);
    nodePolicy.CA_URL =
      getElementValue(nodePolicyElement,
		      NODE_CA_URL_ELEMENT, role);
    nodePolicy.CA_keystore =
      getElementValue(nodePolicyElement,
		      NODE_CA_KEYSTORE_ELEMENT, role);
    nodePolicy.CA_keystorePassword =
      getElementValue(nodePolicyElement,
		      NODE_CA_KEYSTORE_PWD_ELEMENT, role);

    nodePolicy.certDirectoryUrl =
      getElementValue(nodePolicyElement,
		      NODE_CERTDIRURL_ELEMENT, role);
    String type =
      getElementValue(nodePolicyElement,
		      NODE_CERTDIRTYPE_ELEMENT, role);

    if (type.equalsIgnoreCase("NetTools")) {
      nodePolicy.certDirectoryType = NodePolicy.NETTOOLS; 
    }
    else if (type.equalsIgnoreCase("CougaarOpenLdap")) {
      nodePolicy.certDirectoryType = NodePolicy.COUGAAR_OPENLDAP;
    }

    nodePolicy.ou = getElementValue(nodePolicyElement, NODE_OU_ELEMENT, role);
    nodePolicy.o = getElementValue(nodePolicyElement, NODE_O_ELEMENT, role);
    nodePolicy.l = getElementValue(nodePolicyElement, NODE_L_ELEMENT, role);
    nodePolicy.st = getElementValue(nodePolicyElement, NODE_ST_ELEMENT, role);
    nodePolicy.c = getElementValue(nodePolicyElement, NODE_C_ELEMENT, role);


    nodePolicy.keyAlgName =
      getElementValue(nodePolicyElement, NODE_KEYALGNAME_ELEMENT, role);
    nodePolicy.sigAlgName =
      getElementValue(nodePolicyElement, NODE_SIGALGNAME_ELEMENT, role);
    nodePolicy.keysize =
      (Integer.valueOf(getElementValue(nodePolicyElement,
			   NODE_KEYSIZE_ELEMENT, role))).intValue();
    Duration duration = new Duration();
    duration.parse(getElementValue(nodePolicyElement, NODE_VALIDITY_ELEMENT, role));
    nodePolicy.howLong = duration.getDuration();
    return nodePolicy;
  }

  public String getElementValue(Element top, String elementName, String role)
  {
    String value = null;
    String defaultValue = null;
    NodeList conf = top.getElementsByTagName(elementName);
    if (CryptoDebug.debug) {
      System.out.print("Looking up role:" + role + " for " + elementName);
    }
    for (int i = 0 ; i < conf.getLength() ; i++) {
      Element element = (Element) conf.item(i);
      Node child = element.getFirstChild();
      String val = null;

      if (child != null) {
	val = child.getNodeValue();
      }
      else {
	val = "";
      }

      if (element.getAttribute("role") == "") {
	defaultValue = val;
      }
      else if(role != null && role.equals(element.getAttribute("role"))) {
	// Found role
	value = val;
      }
    }
    if (value == null) {
      // If requested role was null: caller wants to have the default value
      // If requested role was not found: we try to find the default value
      value = defaultValue;
    }
    if (CryptoDebug.debug) {
      System.out.println(" - Value:" + value);
    }
    
    return value;
  }

  public CaPolicy readCaPolicy(String caDistinguishedName, String role) 
    throws MalformedURLException, NoSuchFieldException, IllegalAccessException,
	   IOException
  {
    if (CryptoDebug.debug) {
      System.out.println("Reading CA policy" + "for dn : "+ caDistinguishedName + " role : "+role);
    }
    X500Name dn = new X500Name(caDistinguishedName);

    NodeList conf =
      configDoc.getDocumentElement().getElementsByTagName(CA_POLICY_ELEMENT);
    CaPolicy caPolicy = null;

    for (int i = 0 ; i < conf.getLength() ; i++) {
      if (conf.item(i).getNodeType() != org.w3c.dom.Node.ELEMENT_NODE) {
	continue;
      }
      Element caPolicyElement = (Element) conf.item(i);
      X500Name aDN = new X500Name(caPolicyElement.getAttribute("name"));
      System.out.println(" Got aDN is :"+ aDN.toString());
      if (!dn.equals(aDN)) {
	System.out.println(" Not equal cont::");
	continue;
      }
      Element caClientPolicy = getChild(caPolicyElement,
					CA_CLIENT_POLICY_ELEMENT);
      
      caPolicy = new CaPolicy();
      if (standalone) {
	// These fields are used in standalone mode only
	caPolicy.keyStoreFile      = getElementValue(caPolicyElement,
						     CA_KEYSTORE_ELEMENT,
						     role);
	caPolicy.keyStorePassword  = getElementValue(caPolicyElement,
						     CA_KEYSTORE_PWD_ELEMENT,
						     role);
	caPolicy.caCommonName      = getElementValue(caPolicyElement,
						     CA_CN_ELEMENT,
						     role);
	caPolicy.ldapURL           = getElementValue(caPolicyElement,
						     CA_LDAP_URL_ELEMENT,
						     role);

	String type = getElementValue(caPolicyElement,
				      CA_LDAP_TYPE_ELEMENT, role);
	
	if (type != null) {
	  if (type.equalsIgnoreCase("NetTools")) {
	    caPolicy.ldapType = CaPolicy.NETTOOLS; 
	  }
	  else if (type.equalsIgnoreCase("CougaarOpenLdap")) {
	    caPolicy.ldapType = CaPolicy.COUGAAR_OPENLDAP;
	  }
	}
	else {
	  if (CryptoDebug.debug) { 
	    System.out.println("Error !!!!!!! No LDAP server type specified.");
	  }
	}

	String crlalgIdString = getElementValue(caClientPolicy,
						CA_CRL_ALGORITHMID_ELEMENT,
						role);
	//Class crlalgIdClass = AlgorithmId.class;
	Field crlalgIdField =
	  AlgorithmId.class.getDeclaredField(crlalgIdString);
	caPolicy.CRLalgorithmId =
	  new AlgorithmId((ObjectIdentifier)crlalgIdField.get(null));

	String strPending = getElementValue(caClientPolicy,
					    CA_REQUIREPENDING_ELEMENT, role);
	caPolicy.requirePending = false;
	if (strPending != null && strPending.equals("true"))
	  caPolicy.requirePending = true;
      }

      caPolicy.serialNumberFile  = getElementValue(caPolicyElement,
						   CA_SERIAL_NB_FILE_ELEMENT,
						   role);

      caPolicy.pkcs10Directory   = getElementValue(caPolicyElement,
						   CA_PKCS10_DIR_ELEMENT,
						   role);
      caPolicy.x509CertDirectory = getElementValue(caPolicyElement,
						   CA_X509_CERT_DIR_ELEMENT,
						   role);
      caPolicy.pendingDirectory = getElementValue(caPolicyElement,
						  CA_CERT_PENDING_DIR_ELEMENT,
						  role);
      caPolicy.deniedDirectory = getElementValue(caPolicyElement,
						 CA_CERT_DENIED_DIR_ELEMENT,
						 role);

      caPolicy.certVersion = (Integer.valueOf(getElementValue(caClientPolicy,
				 CA_CERTVERSION_ELEMENT, role))).intValue();

      /** Acceptable algorithm ID:
       *  md2WithRSAEncryption_oid
       *  md5WithRSAEncryption_oid
       *  sha1WithRSAEncryption_oid
       *  sha1WithRSAEncryption_OIW_oid
       *  shaWithDSA_OIW_oid
       *  sha1WithDSA_OIW_oid
       *  sha1WithDSA_oid
       */
      String algIdString = getElementValue(caClientPolicy,
					   CA_ALGORITHMID_ELEMENT, role);
      Class algIdClass = AlgorithmId.class;
      Field algIdField = AlgorithmId.class.getDeclaredField(algIdString);
      caPolicy.algorithmId =
	new AlgorithmId((ObjectIdentifier)algIdField.get(null));
      
      
      caPolicy.keySize = (Integer.valueOf(getElementValue(caClientPolicy,
				 CA_KEYSIZE_ELEMENT, role))).intValue();
      Duration duration = new Duration();
      duration.parse(getElementValue(caClientPolicy,
				     CA_CERTVALIDITY_ELEMENT, role));
      caPolicy.howLong = duration.getDuration();
    }
    return caPolicy;
  }

  public X500Name[] getCaDNs()
  {
    X500Name[] caDNs = new X500Name[0];
    ArrayList caList = new ArrayList();

    NodeList conf =
      configDoc.getDocumentElement().getElementsByTagName(CA_POLICY_ELEMENT);

    for (int i = 0 ; i < conf.getLength() ; i++) {
      if (conf.item(i).getNodeType() != org.w3c.dom.Node.ELEMENT_NODE) {
	continue;
      }
      Element element = (Element) conf.item(i);
      try {
	X500Name aDN = new X500Name(element.getAttribute("name"));
	System.out.println(aDN.toString());
	caList.add(aDN);
      }
      catch (Exception e) {
      }
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



