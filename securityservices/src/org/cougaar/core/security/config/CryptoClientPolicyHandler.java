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

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.util.*;
import org.cougaar.core.security.services.util.*;

public class CryptoClientPolicyHandler
  extends BaseConfigHandler
{
  private CryptoClientPolicy cryptoClientPolicy;
  private TrustedCaPolicy currentTrustedCa;
  private CertificateAttributesPolicy currentCertAttr;

  public static final String IS_CERT_AUTH_ELEMENT = "isCertificateAuthority";
  public static final String IS_ROOT_CA_ELEMENT = "isRootCA";
  public static final String CA_KEYSTORE_ELEMENT          = "CA_keystore";
  public static final String CA_KEYSTORE_PASSWORD_ELEMENT = "CA_keystorePassword";

  public static final String KEYSTORE_FILE_ELEMENT          = "keystoreFileName";
  public static final String KEYSTORE_PASSWORD_ELEMENT      = "keystorePassword";
  public static final String KEYSTORE_USE_SMART_CARD        = "keystoreUseSmartCard";

  // Trusted Ca attributes
  public static final String TRUSTED_CA_ELEMENT          = "trustedCA";
  public static final String CA_URL_ELEMENT              = "CA_URL";
  public static final String CA_DN_ELEMENT               = "CA_DN";
  public static final String CERT_DIRECTORY_URL_ELEMENT  = "CertDirectoryURL";
  public static final String CERT_DIRECTORY_TYPE_ELEMENT = "CertDirectoryType";
  public static final String CERT_DIRECTORY_PRINCIPAL_ELEMENT = "CertDirectorySecurityPrincipal";
  public static final String CERT_DIRECTORY_CREDENTIAL_ELEMENT = "CertDirectorySecurityCredential";
  public static final String CA_INFOURL_ELEMENT          = "CA_infoURL";
  public static final String CA_REQUESTURL_ELEMENT          = "CA_requestURL";

  // Certificate Attributes
  public static final String CERTIFICATE_ATTR_ELEMENT = "certificateAttributes";
  //public static final String CACERTIFICATE_ATTR_ELEMENT = "caCertificateAttributes";
  public static final String OU_ELEMENT           = "ou";
  public static final String O_ELEMENT            = "o";
  public static final String L_ELEMENT            = "l";
  public static final String ST_ELEMENT           = "st";
  public static final String C_ELEMENT            = "c";
  public static final String DOMAIN_ELEMENT       = "domain";
  public static final String KEYALGNAME_ELEMENT   = "keyAlgName";
  public static final String SIGALGNAME_ELEMENT   = "sigAlgName";
  public static final String KEYSIZE_ELEMENT      = "keysize";
  public static final String VALIDITY_ELEMENT     = "validity";
  public static final String ENVELOPE_ELEMENT     = "timeEnvelope";
  public static final String NODE_IS_SIGNER_ELEMENT = "nodeIsSigner";

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

    if (localName.equals(TRUSTED_CA_ELEMENT)) {
      currentTrustedCa = new TrustedCaPolicy();
      cryptoClientPolicy.addTrustedCaPolicy(currentTrustedCa);
    }
    if (localName.equals(CERTIFICATE_ATTR_ELEMENT)) {
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

    if (localName.equals(IS_CERT_AUTH_ELEMENT)) {
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

    else if (localName.equals(KEYSTORE_FILE_ELEMENT)) {
      cryptoClientPolicy.setKeystoreName(getContents());
    }
    else if (localName.equals(KEYSTORE_PASSWORD_ELEMENT)) {
      cryptoClientPolicy.setKeystorePassword(getContents());
    }
    else if (localName.equals(KEYSTORE_USE_SMART_CARD)) {
      cryptoClientPolicy.setUseSmartCard(true);
    } // end of if (localName.equals(KEYSTORE_USE_SMART_CARD))

    // trusted CA keystore
    else if (localName.equals(CA_KEYSTORE_ELEMENT)) {
      cryptoClientPolicy.setTrustedCaKeystoreName(getContents());
    }
    else if (localName.equals(CA_KEYSTORE_PASSWORD_ELEMENT)) {
      cryptoClientPolicy.setTrustedCaKeystorePassword(getContents());
    }

    // trusted CA
    /*
    if (localName.equals(CA_ALIAS_ELEMENT)) {
      currentTrustedCa.caAlias = getContents();
    }
    */
    else if (localName.equals(CA_URL_ELEMENT)) {
      currentTrustedCa.caURL = getContents();
    }
    else if (localName.equals(CA_DN_ELEMENT)) {
      currentTrustedCa.caDN = getContents();
    }
    else if (localName.equals(CERT_DIRECTORY_URL_ELEMENT)) {
      currentTrustedCa.certDirectoryUrl = getContents();
    }
    else if (localName.equals(CERT_DIRECTORY_PRINCIPAL_ELEMENT)) {
      currentTrustedCa.certDirectoryPrincipal = getContents();
    }
    else if (localName.equals(CERT_DIRECTORY_CREDENTIAL_ELEMENT)) {
      currentTrustedCa.certDirectoryCredential = getContents();
    }
    else if (localName.equals(CERT_DIRECTORY_TYPE_ELEMENT)) {
      String type = getContents();
      if (type.equalsIgnoreCase("NetTools")) {
	currentTrustedCa.certDirectoryType = TrustedCaPolicy.NETTOOLS;
      }
      else if (type.equalsIgnoreCase("CougaarOpenLdap")) {
	currentTrustedCa.certDirectoryType = TrustedCaPolicy.COUGAAR_OPENLDAP;
      }
    }

    // Certificate attributes
    else if (localName.equals(OU_ELEMENT)) {
      currentCertAttr.ou = getContents();
    }
    else if (localName.equals(O_ELEMENT)) {
      currentCertAttr.o = getContents();
    }
    else if (localName.equals(L_ELEMENT)) {
      currentCertAttr.l = getContents();
    }
    else if (localName.equals(ST_ELEMENT)) {
      currentCertAttr.st = getContents();
    }
    else if (localName.equals(C_ELEMENT)) {
      currentCertAttr.c = getContents();
    }
    else if (localName.equals(DOMAIN_ELEMENT)) {
      currentCertAttr.domain = getContents();
    }
    else if (localName.equals(KEYALGNAME_ELEMENT)) {
      currentCertAttr.keyAlgName = getContents();
    }
    else if (localName.equals(SIGALGNAME_ELEMENT)) {
      currentCertAttr.sigAlgName = getContents();
    }
    else if (localName.equals(KEYSIZE_ELEMENT)) {
      String val = getContents();
      currentCertAttr.keysize = Integer.parseInt(val);
    }
    else if (localName.equals(NODE_IS_SIGNER_ELEMENT)) {
      String val = getContents();
      currentCertAttr.nodeIsSigner = false;
      if (val.equalsIgnoreCase("true")) {
	currentCertAttr.nodeIsSigner = true;
      }
    }

    else if (localName.equals(IS_ROOT_CA_ELEMENT)) {
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

    else if (localName.equals(VALIDITY_ELEMENT)) {
      Duration duration = new Duration(serviceBroker);
      String content = getContents();
      duration.parse(content);
      currentCertAttr.howLong = duration.getDuration();
      currentCertAttr.validity = content;
    }
    else if (localName.equals(ENVELOPE_ELEMENT)) {
      Duration duration = new Duration(serviceBroker);
      String content = getContents();
      duration.parse(content);
      currentCertAttr.regenEnvelope = duration.getDuration();
      currentCertAttr.timeEnvelope = content;
    }
    else if (localName.equals(CA_INFOURL_ELEMENT)) {
      String value = getContents();
      cryptoClientPolicy.setInfoURL(value);
    }
    else if (localName.equals(CA_REQUESTURL_ELEMENT)) {
      String value = getContents();
      cryptoClientPolicy.setRequestURL(value);
    }
    if (localName.equals(TRUSTED_CA_ELEMENT)) {
    // reset TrustedCaPolicy
      currentTrustedCa = null;
    }
  }
}

