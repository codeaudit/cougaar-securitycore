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
import java.util.regex.*;

import sun.security.x509.*;
import sun.security.util.ObjectIdentifier;

// Cougaar security services
import com.nai.security.policy.*;
import com.nai.security.util.*;

public class BaseConfigHandler
  extends DefaultHandler
{
  // Parent...
  protected ContentHandler parent;
  // XML Parser
  protected XMLReader parser;

  // Buffer for collecting data from
  // the "characters" SAX event.
  protected CharArrayWriter contents = new CharArrayWriter();

  protected SecurityPolicy currentSecurityPolicy;

  protected String role;
  private String topLevelTag;


  public SecurityPolicy getSecurityPolicy() {
    return currentSecurityPolicy;
  }

  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String role,
			    String topLevelTag) {
    if (CryptoDebug.debug) {
      System.out.println("Reading policy");
    }
    this.parent = parent;
    this.parser = parser;
    this.role = role;
    this.topLevelTag = topLevelTag;
    parser.setContentHandler(this);
  }

  protected static final int SET_DEFAULT = 1;
  protected static final int SET_VALUE   = 2;
  protected static final int SKIP = 3;
  protected int endElementAction;

  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr )
    throws SAXException {
    contents.reset();
    String currentRole = attr.getValue("role");
    if (CryptoDebug.debug) {
      System.out.println("currentRole=" + currentRole
			 + " - requested role:" + role);
    }
    if (currentRole == null) {
      endElementAction = SET_DEFAULT;
    }
    else if (!currentRole.equals(role)) {
      endElementAction = SKIP;
    }
    else {
      endElementAction = SET_VALUE;
    }
  }
 
  public void endElement( String namespaceURI,
			  String localName,
			  String qName )
    throws SAXException {
    if (localName.equals(topLevelTag) && parent != null) {
      // swap content handler back to parent
      parser.setContentHandler(parent);
    }
  }
 
  public void characters( char[] ch, int start, int length )
    throws SAXException {
    contents.write(ch, start, length);
  }

  public String getContents() {
    Pattern p = Pattern.compile("\\$\\{.*\\}");
    String s = contents.toString();

    /* Search for java properties patterns.
     * ${} will be replaced by the value of the java property.
     * For example:
     *   ${org.cougaar.node.name} will be replaced by the value
     *   of the org.cougaar.node.name java property.
     */
    Matcher m = p.matcher(s);
    StringBuffer sb = new StringBuffer();
    boolean result = m.find();
    // Loop through and create a new String 
    // with the replacements
    while(result) {
      String token = m.group();
      String propertyName = token.substring(2, token.length() - 1);
      String propertyValue = System.getProperty(propertyName);
      System.out.println("Replacing " + token + " with " + propertyValue);
      m.appendReplacement(sb, propertyValue);
      result = m.find();
    }
    // Add the last segment of input to 
    // the new String
    m.appendTail(sb);
    return sb.toString();
  }

 
  /** Receive notification of a notation declaration event.
   */
  public void notationDecl(String name, String publicId, String systemId) {
    if (CryptoDebug.debug) {
      System.out.println("Name: " + name + " publicId: " + publicId
			 + " systemId: " + systemId);
    }
  }

  /** Receive notification of an unparsed entity declaration event.
   */
  public void unparsedEntityDecl(String name, String publicId,
				 String systemId, String notationName) {
    if (CryptoDebug.debug) {
      System.out.println("Name: " + name + " publicId: " + publicId
			 + " notationName: " + notationName);
    }
  }

  /** Allow the application to resolve external entities.
   */
  public InputSource resolveEntity(String publicId, String systemId) {
    InputSource is = null;
    if (CryptoDebug.debug) {
      System.out.println(" publicId: " + publicId
			 + " systemId: " + systemId);
    }
    return is;
  }

}
