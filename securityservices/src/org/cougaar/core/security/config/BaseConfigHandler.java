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
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.util.*;

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

  private Hashtable attributeTable;
  private boolean replaceJavaProperties = true;
  private boolean replaceAttributes = true;

  protected static final int SET_DEFAULT = 1;
  protected static final int SET_VALUE   = 2;
  protected static final int SKIP = 3;
  protected int endElementAction;

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

  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr )
    throws SAXException {
    contents.reset();
    String currentRole = attr.getValue("role");
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
    setContents();
  }

  public void replaceAttributes(boolean value) {
    replaceAttributes = value;
  }
  public void replaceJavaProperties(boolean value) {
    replaceJavaProperties = value;
  }

  public void setAttributeTable(Hashtable hash) {
    attributeTable = hash;
  }

  public String getContents() {
    return contentsValue;
  }

  private String contentsValue;

  protected void setContents() {
    contentsValue = parseContents(contents.toString());
  }

  protected String parseContents(String s) {
    Pattern p_javaprop = Pattern.compile("\\$\\{.*\\}");
    Pattern p_keyvalue = Pattern.compile("\\$\\[.*\\]");
    Matcher matcher = null;
    StringBuffer sb = new StringBuffer();
    boolean result = false;


    if (replaceJavaProperties) {
      if (CryptoDebug.debug) {
	System.out.println("Looking up java property pattern in " + s);
      }
      /* Search for java properties patterns.
     * ${java_property} will be replaced by the value of the java property.
     * For example:
     *   ${org.cougaar.node.name} will be replaced by the value
     *   of the org.cougaar.node.name java property.
     */
      matcher = p_javaprop.matcher(s);
      result = matcher.find();
      // Loop through and create a new String 
      // with the replacements
      while(result) {
	String token = matcher.group();
	String propertyName = token.substring(2, token.length() - 1);
	String propertyValue = System.getProperty(propertyName);
	System.out.println("Replacing " + token + " with " + propertyValue);
	matcher.appendReplacement(sb, propertyValue);
	result = matcher.find();
      }
      // Add the last segment of input to 
      // the new String
      matcher.appendTail(sb);
      s = sb.toString();
    }

    if (attributeTable != null && replaceAttributes) {
      if (CryptoDebug.debug) {
	System.out.println("Looking up attribute pattern in " + s);
      }
      /* Replace attributes with their value.
       * $[attribute] will be replaced by the value of the attribute.
       * For example:
       *   ${attr1} will be replaced by the value
       *   of the attr1 attribute.
       */
      sb.setLength(0);
      matcher = p_keyvalue.matcher(s);
      result = matcher.find();
      // Loop through and create a new String 
      // with the replacements
      while(result) {
	String token = matcher.group();
	String attributeName = token.substring(2, token.length() - 1);
	String attributeValue = (String) attributeTable.get(attributeName);
	System.out.println("Replacing " + token + " with " + attributeValue);
	matcher.appendReplacement(sb, attributeValue);
	result = matcher.find();
      }
      // Add the last segment of input to 
      // the new String
      matcher.appendTail(sb);
      s = sb.toString();
    }
    
    return s;
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
