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
import java.lang.reflect.*;

import sun.security.x509.*;
import sun.security.util.ObjectIdentifier;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.util.*;

public class CaPolicyHandler
  extends BaseConfigHandler
{
  private CaPolicy caPolicy;

  public CaPolicyHandler(ServiceBroker sb) {
    super(sb);
  }

  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String topLevelTag) {
    if (log.isDebugEnabled()) {
      log.debug("Reading CA policy");
    }
    caPolicy = new CaPolicy();
    currentSecurityPolicy = caPolicy;
    super.collectPolicy(parser, parent, topLevelTag);
  }

  public static final String POLICY_ELEMENT = "policy";

  public static final String CA_DN_ELEMENT               = "distinguishedName";
  public static final String CA_LDAP_URL_ELEMENT         = "ldapURL";
  public static final String CA_LDAP_TYPE_ELEMENT        = "ldapType";
  public static final String CA_LDAP_PRINCIPAL_ELEMENT   = "ldapPrincipal";
  public static final String CA_LDAP_CREDENTIAL_ELEMENT  = "ldapCredential";

  public static final String CA_CERTVERSION_ELEMENT      = "certVersion";
  public static final String CA_ALGORITHMID_ELEMENT      = "algorithmId";
  public static final String CA_CRL_ALGORITHMID_ELEMENT  = "crlalgorithmId";
  public static final String CA_KEYSIZE_ELEMENT          = "keysize";
  public static final String CA_CERTVALIDITY_ELEMENT     = "certValidity";
  public static final String CA_TIMEENVELOPE_ELEMENT     = "timeEnvelope";
  public static final String CA_REQUIREPENDING_ELEMENT   = "requirePending";
  public static final String CA_NODE_IS_SIGNER_ELEMENT   = "nodeIsSigner";

  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr )
    throws SAXException {
    super.startElement(namespaceURI, localName, qName, attr);

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
      log.debug("CaPolicy: " + localName
		+ " = " + getContents());
    }

    // Names
    if (localName.equals(CA_DN_ELEMENT)) {
      X500Name aDN = null;
      try {
	aDN = new X500Name(getContents());
	if (log.isDebugEnabled()) {
	  log.debug(" Got aDN is :"+ aDN.toString());
	}
	caPolicy.caDnName = aDN;
	caPolicy.caCommonName = aDN.getCommonName();
      }
      catch (IOException e) {
	if (log.isErrorEnabled()) {
	  log.error("Unable to parse DN");
	}
      }
    }
    // Directories
    /*
    if (localName.equals(CA_SERIAL_ELEMENT)) {
      caPolicy.serialNumberFile = getContents();
    }
    if (localName.equals(CA_PKCS10_ELEMENT)) {
      caPolicy.pkcs10Directory = getContents();
    }
    if (localName.equals(CA_X509_ELEMENT  )) {
      caPolicy.x509CertDirectory = getContents();
    }
    if (localName.equals(CA_PENDING_ELEMENT )) {
      caPolicy.pendingDirectory = getContents();
    }
    if (localName.equals(CA_DENIED_ELEMENT )) {
      caPolicy.deniedDirectory = getContents();
    }
    */

    // Certificate Directory Service
    else if (localName.equals(CA_LDAP_URL_ELEMENT)) {
      caPolicy.ldapURL = getContents();
    }
    else if (localName.equals(CA_LDAP_PRINCIPAL_ELEMENT)) {
      caPolicy.ldapPrincipal = getContents();
    }
    else if (localName.equals(CA_LDAP_CREDENTIAL_ELEMENT)) {
      caPolicy.ldapCredential = getContents();
    }
    else if (localName.equals(CA_LDAP_TYPE_ELEMENT)) {
      String type = getContents();
      if (type != null) {
	if (type.equalsIgnoreCase("NetTools")) {
	  caPolicy.ldapType = CaPolicy.NETTOOLS;
	}
	else if (type.equalsIgnoreCase("CougaarOpenLdap")) {
	  caPolicy.ldapType = CaPolicy.COUGAAR_OPENLDAP;
	}
      }
      else {
	if (log.isErrorEnabled()) {
	  log.error("No LDAP server type specified.");
	}
      }
    }

    // Certificate Policy
    else if (localName.equals(CA_CERTVERSION_ELEMENT)) {
      caPolicy.certVersion = Integer.valueOf(getContents()).intValue();
    }
    else if (localName.equals(CA_ALGORITHMID_ELEMENT)) {
      /** Acceptable algorithm ID:
       *  md2WithRSAEncryption_oid
       *  md5WithRSAEncryption_oid
       *  sha1WithRSAEncryption_oid
       *  sha1WithRSAEncryption_OIW_oid
       *  shaWithDSA_OIW_oid
       *  sha1WithDSA_OIW_oid
       *  sha1WithDSA_oid
       */
      String algIdString = getContents();
      Class algIdClass = AlgorithmId.class;
      Field algIdField = null;
      caPolicy.algIdString = algIdString;
      try {
	algIdField = AlgorithmId.class.getDeclaredField(algIdString);
	caPolicy.algorithmId =
	  new AlgorithmId((ObjectIdentifier)algIdField.get(null));
      }
      catch (NoSuchFieldException e) {
	log.error("Unable to get algorithm identifier");
      }
      catch (IllegalAccessException e) {
	log.error("Unable to get algorithm identifier");
      }
    }

    else if (localName.equals(CA_CRL_ALGORITHMID_ELEMENT)) {
      String crlalgIdString = getContents();
      Field crlalgIdField = null;
      caPolicy.crlAlgIdString = crlalgIdString;
      try {
	crlalgIdField = AlgorithmId.class.getDeclaredField(crlalgIdString);
	caPolicy.CRLalgorithmId =
	  new AlgorithmId((ObjectIdentifier)crlalgIdField.get(null));
      }
      catch (NoSuchFieldException e) {
	log.error("No Such CRL algorithm");
      }
      catch (IllegalAccessException e) {
	log.error("Cannot parse CRL algorithm");
      }
    }
    else if (localName.equals(CA_KEYSIZE_ELEMENT)) {
      caPolicy.keySize = Integer.valueOf(getContents()).intValue();
    }
    else if (localName.equals(CA_CERTVALIDITY_ELEMENT)) {
      Duration duration = new Duration(serviceBroker);
      String content = getContents();
      duration.parse(content);
      caPolicy.howLong = duration.getDuration();
      caPolicy.validity = content;
    }
    else if (localName.equals(CA_TIMEENVELOPE_ELEMENT)) {
      Duration duration = new Duration(serviceBroker);
      String content = getContents();
      duration.parse(content);
      caPolicy.timeEnvelope = duration.getDuration();
      caPolicy.timeEnvelopeString = content;
    }
    else if (localName.equals(CA_REQUIREPENDING_ELEMENT)) {
      String strPending = getContents();
      caPolicy.requirePending = false;
      if (strPending != null && strPending.equals("true"))
	caPolicy.requirePending = true;
    }
    else if (localName.equals(CA_NODE_IS_SIGNER_ELEMENT)) {
      String val = getContents();
      caPolicy.nodeIsSigner = false;
      if (val.equalsIgnoreCase("true")) {
	caPolicy.nodeIsSigner = true;
      }
    }
  }
}

