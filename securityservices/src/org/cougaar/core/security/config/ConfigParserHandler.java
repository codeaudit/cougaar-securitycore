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


package org.cougaar.core.security.config;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.config.jar.JarFileHandler;
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.CryptoPolicy;
import org.cougaar.core.security.policy.DataProtectionPolicy;
import org.cougaar.core.security.policy.PolicyUpdateException;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.service.LoggingService;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

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
  private boolean signJar;

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
    String cougaarWsp = sps.getProperty(SecurityPropertiesService.COUGAAR_WORKSPACE);
    String topDirectory = cougaarWsp + File.separatorChar + "security"
      + File.separatorChar + "keystores" + File.separatorChar;
    String nodeDirectory = topDirectory + nodeName;
    String finderClass = System.getProperty(
      "org.cougaar.util.ConfigFinder.ClassName", null);
    signJar = (finderClass != null &&
      finderClass.equals("org.cougaar.core.security.config.jar.SecureConfigFinder"));
    if (!signJar) {
      cryptoPolicyFileName = nodeDirectory + File.separatorChar + "cryptoPolicy.xml";
    }
    else {
      cryptoPolicyFileName = nodeDirectory + File.separatorChar + "policies.jar";
    }
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
      OutputStream fos = null;
      if (!signJar) {
        fos = new FileOutputStream(policyFile);
      }
      else {
        fos = new ByteArrayOutputStream();
      }
      OutputFormat of = new OutputFormat(updatedPolicy, "US-ASCII", true);
      // no line wrapping
      of.setLineWidth(0);
      // indent 2 spaces
      of.setIndent(2);
      XMLSerializer xs = new XMLSerializer(fos, of);
      xs.serialize(updatedPolicy);

      if (!signJar) {
        fos.flush();
        fos.close();
      }
      else {
        // use jar file
        JarFileHandler jarhandler = JarFileHandler.getHandler(serviceBroker);
        jarhandler.updateJarFile("cryptoPolicy.xml", policyFile,
          (ByteArrayOutputStream)fos);
      }
    }
    catch(Exception e) {
      throw new PolicyUpdateException(e);
    }
    if(log.isDebugEnabled()) {
      log.debug("Saved crypto client policy " + cryptoPolicyFileName);
    }
  }
}
