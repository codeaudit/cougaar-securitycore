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

// Cougaar security services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.util.*;

public class CryptoPolicyHandler 
  extends BaseConfigHandler
{
  private CryptoPolicy cp;

  private static final String POLICY_ELEMENT = "policy";
  private static final String ISM_ELEMENT = "IncomingSecureMethod";
  private static final String OSM_ELEMENT = "OutgoingSecureMethod";
  private static final String ISA_ELEMENT = "IncomingSymmetricAlgorithm";
  private static final String OSA_ELEMENT = "OutgoingSymmetricAlgorithm";
  private static final String IAA_ELEMENT = "IncomingAsymmetricAlgorithm";
  private static final String OAA_ELEMENT = "OutgoingAsymmetricAlgorithm";
  private static final String IS_ELEMENT = "IncomingSigningAlgorithm";
  private static final String OS_ELEMENT = "OutgoingSigningAlgorithm";

  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String role,
			    String topLevelTag) {
    
    if (CryptoDebug.debug) {
      System.out.println("Reading crypto policy");
    }
    cp = new CryptoPolicy();
    currentSecurityPolicy = cp;
    super.collectPolicy(parser, parent, role, topLevelTag);
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

    if (CryptoDebug.debug) {
      System.out.println("CryptoPolicy: " + localName 
			 + " = " + getContents());
    }

    if (localName.equals(ISM_ELEMENT)) {
      String value = getContents();
      cp.setInSecureMethod(value);
    }
    if (localName.equals(ISA_ELEMENT)) {
      String value = getContents();
      cp.setInSymmSpec(value);
    }
    if (localName.equals(IAA_ELEMENT)) {
      String value = getContents();
      cp.setInAsymmSpec(value);
    }
    if (localName.equals(IS_ELEMENT)) {
      String value = getContents();
      cp.setInSignSpec(value);
    }

    if (localName.equals(OSM_ELEMENT)) {
      String value = getContents();
      cp.setOutSecureMethod(value);
    }
    if (localName.equals(OSA_ELEMENT)) {
      String value = getContents();
      cp.setOutSymmSpec(value);
    }
    if (localName.equals(OAA_ELEMENT)) {
      String value = getContents();
      cp.setOutAsymmSpec(value);
    }
    if (localName.equals(OS_ELEMENT)) {
      String value = getContents();
      cp.setOutSignSpec(value);
    }
  }
  
}
