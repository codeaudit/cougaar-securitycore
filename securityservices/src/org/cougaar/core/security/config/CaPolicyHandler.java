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

import java.io.IOException;
import java.lang.reflect.Field;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.policy.CaPolicyConstants;
import org.cougaar.core.security.util.Duration;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

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
    if (localName.equals(CaPolicyConstants.CA_DN_ELEMENT)) {
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
    if (localName.equals(CaPolicyConstants.CA_SERIAL_ELEMENT)) {
      caPolicy.serialNumberFile = getContents();
    }
    if (localName.equals(CaPolicyConstants.CA_PKCS10_ELEMENT)) {
      caPolicy.pkcs10Directory = getContents();
    }
    if (localName.equals(CaPolicyConstants.CA_X509_ELEMENT  )) {
      caPolicy.x509CertDirectory = getContents();
    }
    if (localName.equals(CaPolicyConstants.CA_PENDING_ELEMENT )) {
      caPolicy.pendingDirectory = getContents();
    }
    if (localName.equals(CaPolicyConstants.CA_DENIED_ELEMENT )) {
      caPolicy.deniedDirectory = getContents();
    }
    */

    // Certificate Directory Service
    else if (localName.equals(CaPolicyConstants.CA_LDAP_URL_ELEMENT)) {
      caPolicy.ldapURL = getContents();
      if (log.isDebugEnabled()) {
        log.debug("Got LDAP:" + caPolicy.ldapURL);
      }
    }
    else if (localName.equals(CaPolicyConstants.CA_LDAP_PRINCIPAL_ELEMENT)) {
      caPolicy.ldapPrincipal = getContents();
    }
    else if (localName.equals(CaPolicyConstants.CA_LDAP_CREDENTIAL_ELEMENT)) {
      caPolicy.ldapCredential = getContents();
    }
    else if (localName.equals(CaPolicyConstants.CA_LDAP_TYPE_ELEMENT)) {
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
    else if (localName.equals(CaPolicyConstants.CA_CERTVERSION_ELEMENT)) {
      caPolicy.certVersion = Integer.valueOf(getContents()).intValue();
    }
    else if (localName.equals(CaPolicyConstants.CA_ALGORITHMID_ELEMENT)) {
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
      //Class algIdClass = AlgorithmId.class;
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

    else if (localName.equals(CaPolicyConstants.CA_CRL_ALGORITHMID_ELEMENT)) {
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
    else if (localName.equals(CaPolicyConstants.CA_KEYSIZE_ELEMENT)) {
      caPolicy.keySize = Integer.valueOf(getContents()).intValue();
    }
    else if (localName.equals(CaPolicyConstants.CA_CERTVALIDITY_ELEMENT)) {
      Duration duration = new Duration(serviceBroker);
      String content = getContents();
      duration.parse(content);
      caPolicy.howLong = duration.getDuration();
      caPolicy.validity = content;
    }
    else if (localName.equals(CaPolicyConstants.CA_TIMEENVELOPE_ELEMENT)) {
      Duration duration = new Duration(serviceBroker);
      String content = getContents();
      duration.parse(content);
      caPolicy.timeEnvelope = duration.getDuration();
      caPolicy.timeEnvelopeString = content;
    }
    else if (localName.equals(CaPolicyConstants.CA_REQUIREPENDING_ELEMENT)) {
      String strPending = getContents();
      caPolicy.requirePending = false;
      if (strPending != null && strPending.equals("true"))
	caPolicy.requirePending = true;
    }
    else if (localName.equals(CaPolicyConstants.CA_NODE_IS_SIGNER_ELEMENT)) {
      String val = getContents();
      caPolicy.nodeIsSigner = false;
      if (val.equalsIgnoreCase("true")) {
	caPolicy.nodeIsSigner = true;
      }
    }
    writerReset();
  }
}

