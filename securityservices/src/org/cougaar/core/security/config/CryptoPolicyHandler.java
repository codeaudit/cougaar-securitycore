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
import org.cougaar.core.security.policy.AccessControlPolicy;
import org.cougaar.core.security.policy.CryptoPolicy;
import org.cougaar.core.security.policy.PersistenceManagerPolicy;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

public class CryptoPolicyHandler
  extends BaseConfigHandler
{
  private CryptoPolicy cp;
  private String msgParty;

  private static final String POLICY_ELEMENT = "PolicyEntry";
  private static final String PARTY_ELEMENT = "MsgParty";
  private static final String ISM_ELEMENT = "SecureMethod";
  private static final String ISA_ELEMENT = "SymmetricAlgorithm";
  private static final String IAA_ELEMENT = "AsymmetricAlgorithm";
  private static final String IS_ELEMENT = "SigningAlgorithm";
  //private static final String PMS_ELEMENT = "PersistenceManagers";
  private static final String PM_ELEMENT = "PersistenceManager";
  private static final String PMTYPE_ELEMENT = "PMType";
  private static final String PMURL_ELEMENT = "PM_URL";
  private static final String PMDN_ELEMENT = "PM_DN";

  private String msgCom;
  private PersistenceManagerPolicy pmPolicy;

  public CryptoPolicyHandler(ServiceBroker sb) {
    super(sb);
  }

  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String topLevelTag) {

    if (log.isDebugEnabled()) {
      log.debug("Reading crypto policy");
    }
    cp = new CryptoPolicy();
    currentSecurityPolicy = cp;
    super.collectPolicy(parser, parent, topLevelTag);
  }
  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr )
    throws SAXException {
    super.startElement(namespaceURI, localName, qName, attr);

    if (localName.equals(POLICY_ELEMENT)) {
      msgParty = "";
      msgCom = "";
    }
    if (localName.equals(PM_ELEMENT)) {
      pmPolicy = new PersistenceManagerPolicy();
    }
  }

  public void endElement( String namespaceURI,
			  String localName,
			  String qName )
    throws SAXException {
    super.endElement(namespaceURI, localName, qName);
    if (endElementAction == SKIP) {
      return;
    }

    if (localName.equals("Name")) {
      String value = getContents();
      cp.Name = value;
    }

    if (localName.equals("Type")) {
      String value = getContents();
      if(value.equalsIgnoreCase("AGENT")){
        cp.Type = AccessControlPolicy.AGENT;
      }else if(value.equalsIgnoreCase("COMMUNITY")){
        cp.Type = AccessControlPolicy.COMMUNITY;
      }else if(value.equalsIgnoreCase("SOCIETY")){
        cp.Type = AccessControlPolicy.SOCIETY;
      }else{
        if (log.isErrorEnabled()) {
          log.error(" unexpected Type value.");
        }
      }
    }

    if (localName.equals("Direction")) {
      String value = getContents();
      if(value.equalsIgnoreCase("BOTH")){
        cp.Direction = AccessControlPolicy.BOTH;
      }else if(value.equalsIgnoreCase("INCOMING")){
        cp.Direction = AccessControlPolicy.INCOMING;
      }else if(value.equalsIgnoreCase("OUTGOING")){
        cp.Direction = AccessControlPolicy.OUTGOING;
      }else if(value.equalsIgnoreCase("DATAPROTECTION")){
        cp.Direction = CryptoPolicy.DATAPROTECTION;
      }else{
        if (log.isErrorEnabled()) {
          log.error(" unexpected Direction value.");
        }
      }
    }

    if (log.isDebugEnabled()) {
      log.debug("CryptoPolicy: " + localName
		+ " = " + getContents());
    }

    if (localName.equals(PARTY_ELEMENT)) {
      msgParty = getContents();
    }
    if (localName.equals(ISM_ELEMENT)) {
      String value = getContents();
      cp.setSecuMethod(msgParty,value);
    }
    if (localName.equals(ISA_ELEMENT)) {
      String value = getContents();
      cp.setSymmSpec(msgParty,value);
    }
    if (localName.equals(IAA_ELEMENT)) {
      String value = getContents();
      cp.setAsymmSpec(msgParty,value);
    }
    if (localName.equals(IS_ELEMENT)) {
      String value = getContents();
      cp.setSignSpec(msgParty,value);
    }

    //now for community
    if (localName.equals("MsgCommunity")) {
      msgCom = getContents();
    }
    if (localName.equals("ComSecureMethod")) {
      String value = getContents();
      cp.setComSecuMethod(msgCom,value);
    }
    if (localName.equals("ComSymmetricAlgorithm")) {
      String value = getContents();
      cp.setComSymmSpec(msgCom,value);
    }
    if (localName.equals("ComAsymmetricAlgorithm")) {
      String value = getContents();
      cp.setComAsymmSpec(msgCom,value);
    }
    if (localName.equals("ComSigningAlgorithm")) {
      String value = getContents();
      cp.setComSignSpec(msgCom,value);
    }
    if (localName.equals(PM_ELEMENT)) {
      cp.addPersistenceManagerPolicy(pmPolicy);
    }
    if (localName.equals(PMTYPE_ELEMENT)) {
      String value = getContents();
      pmPolicy.pmType = value;
    }
    if (localName.equals(PMDN_ELEMENT)) {
      String value = getContents();
      pmPolicy.pmDN = value;
    }
    if (localName.equals(PMURL_ELEMENT)) {
      String value = getContents();
      pmPolicy.pmUrl = value;
    }

    // Reset contents
    writerReset();
  }

}
