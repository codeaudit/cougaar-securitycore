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

import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.jdom.input.*;

import java.security.cert.*;
import java.security.KeyStore;
import java.util.*;
import java.net.*;
import java.io.*;
import java.lang.reflect.*;

import sun.security.x509.*;
import sun.security.util.ObjectIdentifier;

import com.nai.security.policy.*;

/** Helper class to read the cryptographic service configuration.
 * 
 */
public class ConfParser {

  private String configFile = null;
  private Document configDoc = null;
  private boolean debug = true;

  public ConfParser() {
    init();
  }

  public Document getConfigDocument() {
    return configDoc;
  }

  public void init() {
    //String installpath = System.getProperty("org.cougaar.install.path");
    String defaultConfigFile = /*installpath + File.separatorChar
      + "configs" + File.separatorChar + "common"
      + File.separatorChar + */"cryptoPolicy.xml";

    configFile = System.getProperty("org.cougaar.security.crypto.config", defaultConfigFile);
    
    try{
      SAXBuilder builder = new SAXBuilder();
      configDoc = builder.build(new File(configFile));
    } catch(JDOMException e) {
      e.printStackTrace();
    } catch(NullPointerException e) {
      e.printStackTrace();
    }
  }

  public List getChildren(String elementName) {
    List children = configDoc.getRootElement().getChildren(elementName);
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

  public static final String NODE_CERTDIRURL_ELEMENT  = "CertDirectoryURL";

  // CA policy
  public static final String CA_POLICY_ELEMENT         = "certificateAuthority";
  public static final String CA_KEYSTORE_ELEMENT       = "keystoreFile";
  public static final String CA_KEYSTORE_PWD_ELEMENT   = "keystorePassword";
  public static final String CA_CN_ELEMENT             = "caCommonName";
  public static final String CA_LDAP_URL_ELEMENT       = "ldapURL";
  public static final String CA_SERIAL_NB_FILE_ELEMENT = "serialNumberFile";
  public static final String CA_PKCS10_DIR_ELEMENT     = "pkcs10Directory";
  public static final String CA_X509_CERT_DIR_ELEMENT  = "x509CertDirectory";

  public static final String CA_CLIENT_POLICY_ELEMENT  = "clientCertPolicy";

  public static final String CA_CERTVERSION_ELEMENT    = "certVersion";
  public static final String CA_ALGORITHMID_ELEMENT    = "algorithmId";
  public static final String CA_KEYSIZE_ELEMENT        = "keysize";
  public static final String CA_CERTVALIDITY_ELEMENT   = "certValidity";

  public void iterate(String name) {
    List conf = configDoc.getRootElement().getChildren(name);
    Iterator it = conf.iterator();
    while (it.hasNext()) {
    }
  }

  public NodePolicy readNodePolicy(String role)
    throws NoSuchFieldException, IllegalAccessException
  {
    if (debug) {
      System.out.println("Readind node policy");
    }
    Element nodePolicyElement = configDoc.getRootElement().getChild(NODE_POLICY_ELEMENT);
    NodePolicy nodePolicy = new NodePolicy();

    nodePolicy.CA_DN = nodePolicyElement.getChildText(NODE_CA_DN_ELEMENT);
    nodePolicy.CA_URL = nodePolicyElement.getChildText(NODE_CA_URL_ELEMENT);
    nodePolicy.CA_keystore = nodePolicyElement.getChildText(NODE_CA_KEYSTORE_ELEMENT);
    nodePolicy.CA_keystorePassword = nodePolicyElement.getChildText(NODE_CA_KEYSTORE_PWD_ELEMENT);

    nodePolicy.certDirectoryURL = getElementValue(nodePolicyElement, NODE_CERTDIRURL_ELEMENT, role);


    nodePolicy.ou = nodePolicyElement.getChildText(NODE_OU_ELEMENT);
    nodePolicy.o = nodePolicyElement.getChildText(NODE_O_ELEMENT);
    nodePolicy.l = nodePolicyElement.getChildText(NODE_L_ELEMENT);
    nodePolicy.st = nodePolicyElement.getChildText(NODE_ST_ELEMENT);
    nodePolicy.c = nodePolicyElement.getChildText(NODE_C_ELEMENT);


    nodePolicy.keyAlgName = nodePolicyElement.getChildText(NODE_KEYALGNAME_ELEMENT);
    nodePolicy.sigAlgName = nodePolicyElement.getChildText(NODE_SIGALGNAME_ELEMENT);
    nodePolicy.keysize = (Integer.valueOf(nodePolicyElement.getChildText(NODE_KEYSIZE_ELEMENT))).intValue();
    nodePolicy.validity = (Integer.valueOf(nodePolicyElement.getChildText(NODE_VALIDITY_ELEMENT))).intValue();
    return nodePolicy;
  }

  public String getElementValue(Element top, String elementName, String role)
  {
    String value = null;
    List conf = top.getChildren(elementName);
    if (debug) {
      System.out.println("Looking up role:" + role );
    }
    Iterator it = conf.iterator();
    while (it.hasNext()) {
      Element element = (Element) it.next();
      /*
      if (debug) {
	System.out.println("text:" + element.getText() + " - attribute role: " 
			   + element.getAttributeValue("role") );
      }
      */
      if (role == null) {
	if (element.getAttributeValue("role") == null) {
	  value = element.getText();
	}
      }
      else {
	if (role.equals(element.getAttributeValue("role"))) {
	  // Found role
	  value = element.getText();
	}
      }
    }
    if (debug) {
      System.out.println("Found value:" + value);
    }
    
    return value;
  }

  public CaPolicy readCaPolicy(String caDistinguishedName, String role) 
    throws MalformedURLException, NoSuchFieldException, IllegalAccessException,
	   IOException
  {
    if (debug) {
      System.out.println("Readind CA policy");
    }
    X500Name dn = new X500Name(caDistinguishedName);

    List conf = configDoc.getRootElement().getChildren(CA_POLICY_ELEMENT);
    Iterator it = conf.iterator();
    CaPolicy caPolicy = null;

    while (it.hasNext()) {
      Element caPolicyElement = (Element) it.next();
      X500Name aDN = new X500Name(caPolicyElement.getAttributeValue("name"));
      if (!dn.equals(aDN)) {
	continue;
      }
      Element caClientPolicy = caPolicyElement.getChild(CA_CLIENT_POLICY_ELEMENT);
      
      caPolicy = new CaPolicy();
      caPolicy.keyStoreFile      = caPolicyElement.getChildText(CA_KEYSTORE_ELEMENT);
      caPolicy.keyStorePassword  = caPolicyElement.getChildText(CA_KEYSTORE_PWD_ELEMENT);
      caPolicy.caCommonName      = caPolicyElement.getChildText(CA_CN_ELEMENT);
      caPolicy.ldapURL           = getElementValue(caPolicyElement, CA_LDAP_URL_ELEMENT, role);

      //caPolicy.ldapURL           = caPolicyElement.getChildText(CA_LDAP_URL_ELEMENT);
      caPolicy.serialNumberFile  = caPolicyElement.getChildText(CA_SERIAL_NB_FILE_ELEMENT);

      caPolicy.pkcs10Directory   = caPolicyElement.getChildText(CA_PKCS10_DIR_ELEMENT);
      caPolicy.x509CertDirectory = caPolicyElement.getChildText(CA_X509_CERT_DIR_ELEMENT);

      caPolicy.certVersion = (Integer.valueOf(caClientPolicy.getChildText(CA_CERTVERSION_ELEMENT))).intValue();

      /** Acceptable algorithm ID:
       *  md2WithRSAEncryption_oid
       *  md5WithRSAEncryption_oid
       *  sha1WithRSAEncryption_oid
       *  sha1WithRSAEncryption_OIW_oid
       *  shaWithDSA_OIW_oid
       *  sha1WithDSA_OIW_oid
       *  sha1WithDSA_oid
       */
      String algIdString = caClientPolicy.getChildText(CA_ALGORITHMID_ELEMENT);
      Class algIdClass = AlgorithmId.class;
      Field algIdField = AlgorithmId.class.getDeclaredField(algIdString);
      caPolicy.algorithmId = new AlgorithmId((ObjectIdentifier)algIdField.get(null));
      
      caPolicy.keySize = (Integer.valueOf(caClientPolicy.getChildText(CA_KEYSIZE_ELEMENT))).intValue();
      caPolicy.howLong = (Integer.valueOf(caClientPolicy.getChildText(CA_CERTVALIDITY_ELEMENT))).intValue(); 
    }
    return caPolicy;
  }
}
