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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.CertificateAttributesPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicyConstants;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.util.CryptoDebug;
import org.cougaar.core.security.util.Duration;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

public class CryptoClientPolicyHandler
  extends BaseConfigHandler
{
  private CryptoClientPolicy cryptoClientPolicy;
  private TrustedCaPolicy currentTrustedCa;
  private CertificateAttributesPolicy currentCertAttr;

  public CryptoClientPolicyHandler(ServiceBroker sb) {
    super(sb);
  }

  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String topLevelTag) {

    if (log.isDebugEnabled()) {
      log.debug("Reading crypto client policy");
    }
    cryptoClientPolicy = new CryptoClientPolicy();
    currentSecurityPolicy = cryptoClientPolicy;
    super.collectPolicy(parser, parent, topLevelTag);
  }

  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr )
    throws SAXException {
    super.startElement(namespaceURI, localName, qName, attr);

    if (localName.equals(CryptoClientPolicyConstants.TRUSTED_CA_ELEMENT)) {
      currentTrustedCa = new TrustedCaPolicy();
      cryptoClientPolicy.addTrustedCaPolicy(currentTrustedCa);
    }
    if (localName.equals(CryptoClientPolicyConstants.CERTIFICATE_ATTR_ELEMENT)) {
    // default cert attribute
      currentCertAttr = new CertificateAttributesPolicy();
      if (currentTrustedCa != null) {
        currentTrustedCa.setCertificateAttributesPolicy(currentCertAttr);
      }
      else {
        cryptoClientPolicy.setCertificateAttributesPolicy(currentCertAttr);
      }
    }
    /*
    if (localName.equals(CACERTIFICATE_ATTR_ELEMENT)) {
    // cert attribute for specific CA
      currentCertAttr = new CertificateAttributesPolicy();
      currentTrustedCa.setCertificateAttributesPolicy(currentCertAttr);
    }
    */

  }

  public void endElement( String namespaceURI,
			  String localName,
			  String qName )
    throws SAXException {
    super.endElement(namespaceURI, localName, qName);
    if (endElementAction == SKIP) {
      return;
    }

    if (log.isDebugEnabled()) {
      log.debug("CryptoClientPolicy: " + localName
		+ " = " + getContents());
    }

    if (localName.equals(CryptoClientPolicyConstants.IS_CERT_AUTH_ELEMENT)) {
      String st_value = getContents();
      boolean value = false;
      if (st_value.equalsIgnoreCase("true")) {
	value = true;
      }
      if (log.isInfoEnabled()) {
	if (value) {
	  log.info("Running as a Certificate Authority");
	}
	else {
	  log.info("Running as a standard Cougaar node");
	}
      }
      cryptoClientPolicy.setIsCertificateAuthority(value);
    }

    else if (localName.equals(CryptoClientPolicyConstants.KEYSTORE_FILE_ELEMENT)) {
      cryptoClientPolicy.setKeystoreName(getContents());
    }
    else if (localName.equals(CryptoClientPolicyConstants.KEYSTORE_PASSWORD_ELEMENT)) {
      cryptoClientPolicy.setKeystorePassword(getContents());
    }
    else if (localName.equals(CryptoClientPolicyConstants.KEYSTORE_USE_SMART_CARD)) {
      cryptoClientPolicy.setUseSmartCard(true);
    } // end of if (localName.equals(KEYSTORE_USE_SMART_CARD))

    // trusted CA keystore
    else if (localName.equals(CryptoClientPolicyConstants.CA_KEYSTORE_ELEMENT)) {
      cryptoClientPolicy.setTrustedCaKeystoreName(getContents());
    }
    else if (localName.equals(CryptoClientPolicyConstants.CA_KEYSTORE_PASSWORD_ELEMENT)) {
      cryptoClientPolicy.setTrustedCaKeystorePassword(getContents());
    }

    // trusted CA
    /*
    if (localName.equals(CA_ALIAS_ELEMENT)) {
      currentTrustedCa.caAlias = getContents();
    }
    */
    else if (localName.equals(CryptoClientPolicyConstants.CA_URL_ELEMENT)) {
      currentTrustedCa.caURL = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.CA_DN_ELEMENT)) {
      currentTrustedCa.caDN = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.CERT_DIRECTORY_URL_ELEMENT)) {
      currentTrustedCa.certDirectoryUrl = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.CERT_DIRECTORY_PRINCIPAL_ELEMENT)) {
      currentTrustedCa.certDirectoryPrincipal = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.CERT_DIRECTORY_CREDENTIAL_ELEMENT)) {
      currentTrustedCa.certDirectoryCredential = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.CERT_DIRECTORY_TYPE_ELEMENT)) {
      String type = getContents();
      if (type.equalsIgnoreCase("NetTools")) {
	currentTrustedCa.certDirectoryType = TrustedCaPolicy.NETTOOLS;
      }
      else if (type.equalsIgnoreCase("CougaarOpenLdap")) {
	currentTrustedCa.certDirectoryType = TrustedCaPolicy.COUGAAR_OPENLDAP;
      }
    }

    // Certificate attributes
    else if (localName.equals(CryptoClientPolicyConstants.OU_ELEMENT)) {
      currentCertAttr.ou = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.O_ELEMENT)) {
      currentCertAttr.o = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.L_ELEMENT)) {
      currentCertAttr.l = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.ST_ELEMENT)) {
      currentCertAttr.st = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.C_ELEMENT)) {
      currentCertAttr.c = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.DOMAIN_ELEMENT)) {
      currentCertAttr.domain = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.KEYALGNAME_ELEMENT)) {
      currentCertAttr.keyAlgName = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.SIGALGNAME_ELEMENT)) {
      currentCertAttr.sigAlgName = getContents();
    }
    else if (localName.equals(CryptoClientPolicyConstants.KEYSIZE_ELEMENT)) {
      String val = getContents();
      currentCertAttr.keysize = Integer.parseInt(val);
    }
    else if (localName.equals(CryptoClientPolicyConstants.NODE_IS_SIGNER_ELEMENT)) {
      String val = getContents();
      currentCertAttr.nodeIsSigner = false;
      if (val.equalsIgnoreCase("true")) {
	currentCertAttr.nodeIsSigner = true;
      }
    }

    else if (localName.equals(CryptoClientPolicyConstants.IS_ROOT_CA_ELEMENT)) {
      String st_value = getContents();
      boolean value = true;
      if (st_value.equalsIgnoreCase("false")) {
	value = false;
      }
      if (CryptoDebug.debug) {
	if (value) {
      if(log.isDebugEnabled())
        log.debug("Running as Root Certificate Authority");
	}
	else {
      if(log.isDebugEnabled())
        log.debug("Running as a delegate Certificate Authority");
	}
      }
      cryptoClientPolicy.setIsRootCA(value);
    }

    else if (localName.equals(CryptoClientPolicyConstants.VALIDITY_ELEMENT)) {
      Duration duration = new Duration(serviceBroker);
      String content = getContents();
      duration.parse(content);
      currentCertAttr.howLong = duration.getDuration();
      currentCertAttr.validity = content;
    }
    else if (localName.equals(CryptoClientPolicyConstants.ENVELOPE_ELEMENT)) {
      Duration duration = new Duration(serviceBroker);
      String content = getContents();
      duration.parse(content);
      currentCertAttr.regenEnvelope = duration.getDuration();
      currentCertAttr.timeEnvelope = content;
    }
    else if (localName.equals(CryptoClientPolicyConstants.CA_INFOURL_ELEMENT)) {
      String value = getContents();
      cryptoClientPolicy.setInfoURL(value);
    }
    else if (localName.equals(CryptoClientPolicyConstants.CA_REQUESTURL_ELEMENT)) {
      String value = getContents();
      cryptoClientPolicy.setRequestURL(value);
    }
    if (localName.equals(CryptoClientPolicyConstants.TRUSTED_CA_ELEMENT)) {
    // reset TrustedCaPolicy
      currentTrustedCa = null;
    }
    writerReset();
  }
}

