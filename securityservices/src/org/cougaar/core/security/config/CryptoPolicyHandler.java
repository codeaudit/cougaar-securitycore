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
 * Created on May 1, 2002, 2:54 PM
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

  private String msgCom;
  
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

    // Reset contents
    contents.reset();
  }

}
