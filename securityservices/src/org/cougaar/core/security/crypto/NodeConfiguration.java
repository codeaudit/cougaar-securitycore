/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.crypto;

import java.io.File;
import java.io.IOException;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.service.LoggingService;
import org.w3c.dom.Element;

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

    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class, null);

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

    String cougaarWsp=secprop.getProperty(SecurityPropertiesService.COUGAAR_WORKSPACE);
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
      String nodeConfigDirectory = nodeDirectory + File.separatorChar
	+ "configs";
      File nodeConfigDir = new File(nodeConfigDirectory);
      if (!nodeConfigDir.exists()) {
	nodeConfigDir.mkdirs();
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
	}
      }
    }
    */
  }

}
