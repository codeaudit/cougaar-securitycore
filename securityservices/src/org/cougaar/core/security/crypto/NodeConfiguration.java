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

package org.cougaar.core.security.crypto;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

import org.w3c.dom.*;
import sun.security.x509.X500Name;

// Cougaar core infrastructure
import org.cougaar.util.*;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;


// Cougaar security services
import org.cougaar.core.security.util.CryptoDebug;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.provider.SecurityServiceProvider;

public class NodeConfiguration
{
  //private javax.servlet.ServletContext context=null;
  private SecurityPropertiesService secprop;
  private String nodeDirectory;
  private String nodeDomain;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  public NodeConfiguration(String nodeDomain, ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
	serviceBroker.getService(this,
				 LoggingService.class, null);
    log.debug("Node Crypto Initializing");
    // TODO. Modify following line to use service broker instead
    secprop = SecurityServiceProvider.getSecurityProperties(null);

    this.nodeDomain = nodeDomain;
    createDirectoryStructure(this.nodeDomain);
  }

  public void createDomainDirectories(String aDomain)
    throws IOException {

    /*
    String domainDir = nodeDirectory +
      CertificateUtility.getX500Domain(aDomain,
				       false,
				       File.separatorChar, false) + File.separatorChar;
    */
    String domainDir = nodeDirectory;

    String x509DirectoryName =  domainDir + "x509certificates" + File.separatorChar;
    String pkcs10DirectoryName = domainDir + "pkcs10requests" + File.separatorChar;
    String pendingDirectoryName = domainDir + "pendingrequests" + File.separatorChar;
    String deniedDirectoryName = domainDir + "denied" + File.separatorChar;

    File pkcs10dir = new File(pkcs10DirectoryName);
    if (!pkcs10dir.exists()) {
      pkcs10dir.mkdirs();
    }
    
    File x509dir = new File(x509DirectoryName);
    if (!x509dir.exists()) {
      x509dir.mkdirs();
    }

    File pendingDir = new File(pendingDirectoryName);
    if (!pendingDir.exists()) {
      pendingDir.mkdirs();
    }

    File deniedDir = new File(deniedDirectoryName);
    if (!deniedDir.exists()) {
      deniedDir.mkdirs();
    }
  }

  /**
   * The following directory structure will be created automatically
   * when running as a node:
   * + cougaar.workspace
   * +-+ security
   *   +-+ keystore
   *     +-+ <node name>
   *       +-- <keystore file>     (this is the node keystore file)
   *       +-- <CA keystore file>  (the keystore containing trusted CAs)
   *       +-- <serial number file>
   *       +-+ domain              (one sub-directory for each domain component)
   *         +-+ <pkcs10Directory>
   *         | +-- pkcs10 requests
   *         +-+ <x509CertDirectory>
   *         | +-- signed X509 certificates
   *         +-+ <pendingCertDirectory>
   *         | +-- pending X509 certificates
   *         +-+ <deniedCertDirectory>
   *           +-- denied X509 certificates
   *
   */
    
  private void createDirectoryStructure(String aDomain) {
    String nodeName = secprop.getProperty("org.cougaar.node.name");

    String cougaarWsp=secprop.getProperty(secprop.COUGAAR_WORKSPACE);
    log.debug("Cougaar workspace is :" + cougaarWsp);

    String topDirectory = cougaarWsp + File.separatorChar + "security"
      + File.separatorChar + "keystores" + File.separatorChar;

    nodeDirectory = topDirectory + nodeName + File.separatorChar;
    log.debug("Node-level directory: " + nodeDirectory);

    try {
      if (log.isDebugEnabled()) {
	log.debug("Creating directory structure under "
			   + nodeDirectory);
      }
      
      File nodeDir = new File(nodeDirectory);
      if (!nodeDir.exists()) {
	nodeDir.mkdirs();
      }

      createDomainDirectories(aDomain);
    }
    catch (IOException e) {
      log.debug("Unable to create directory structure: " + e);
    }
  }

  public String getNodeDirectory() {
    return nodeDirectory;
  }

  public String getX509DirectoryName(String aDomain) {
    String domainDir = nodeDirectory +
      CertificateUtility.getX500Domain(aDomain,
				       false,
				       File.separatorChar, false);
    String x509DirectoryName =  domainDir + "x509certificates" + File.separatorChar;
    return x509DirectoryName;
  }

  public String getPendingDirectoryName(String aDomain) {
    String domainDir = nodeDirectory +
      CertificateUtility.getX500Domain(aDomain,
				       false,
				       File.separatorChar, false);
    String pendingDirectoryName = domainDir + "pendingrequests" + File.separatorChar;
    return pendingDirectoryName;
  }

  public String getPkcs10DirectoryName(String aDomain) {
    String domainDir = nodeDirectory +
      CertificateUtility.getX500Domain(aDomain,
				       false,
				       File.separatorChar, false);
    String pkcs10DirectoryName = domainDir + "pkcs10requests" + File.separatorChar;
    return pkcs10DirectoryName;
  }

  public String getDeniedDirectoryName(String aDomain) {
    String domainDir = nodeDirectory +
      CertificateUtility.getX500Domain(aDomain,
				       false,
				       File.separatorChar, false);
    String deniedDirectoryName = domainDir + "denied" + File.separatorChar;
    return deniedDirectoryName;
  }

  public void setjavaproperty(Element root)
  {
    /*
    //javax.servlet.ServletContext context=null;
    CryptoDebug.initContext(servlet);

    NodeList children = root.getChildNodes();

    // Iterate through javaproperty
    for (int i = 0 ; i < children.getLength() ; i++) {
      Node o = children.item(i);
      if (o instanceof Element &&
	  ((Element)o).getTagName().equals("servletjavaproperties")) {
	Element propertyelement = (Element)o;
	String propertyName =  getChildText(propertyelement,
					    "propertyname");
	String propertyValue = getChildText(propertyelement,
					    "propertyvalue");
	if((propertyName==null )||(propertyValue==null)) {
	  log.debug("wrong xml format error");
	  return;
	}
	try {
	  log.debug("setting property name in context  :"
			     +propertyName);
	  log.debug("setting property value in context::"
			     +propertyValue);
	  secprop.setProperty(propertyName,propertyValue);
	}
	catch(SecurityException sexp) {
	  sexp.printStackTrace();
	}
      }
    }
    */
  }

}
