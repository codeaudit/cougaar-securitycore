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

import java.io.CharArrayWriter;
import java.util.Hashtable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.service.LoggingService;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

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

  protected ServiceBroker serviceBroker;
  protected LoggingService log;

  protected String role;
  /** The name of the community of type SecurityCommunity. */
  private String mySecurityCommunity;

  private String topLevelTag;

  private Hashtable attributeTable;
  private boolean replaceJavaProperties = true;
  private boolean replaceAttributes = true;

  protected static final int SET_DEFAULT = 1;
  protected static final int SET_VALUE   = 2;
  protected static final int SKIP = 3;
  protected int endElementAction;

  public BaseConfigHandler(ServiceBroker sb) {
    serviceBroker = sb;
    if(sb != null) {
      log = (LoggingService)
        serviceBroker.getService(this,
		  	       LoggingService.class, null);
    }
  }

  public SecurityPolicy getSecurityPolicy() {
    return currentSecurityPolicy;
  }

  protected void writerReset() {
    contents.reset();
    contents.write(0);
    contents.reset();
  }

  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String topLevelTag) {
    if (log.isDebugEnabled()) {
      log.debug("Reading policy");
    }
    this.parent = parent;
    this.parser = parser;
    this.topLevelTag = topLevelTag;
    parser.setContentHandler(this);
  }

  public void setRole(String role) {
    this.role = role;
  }
  public String getRole() {
    return role;
  }
  public void setSecurityCommunity(String community) {
    this.mySecurityCommunity = community;
  }
  public String getSecurityCommunity() {
    return mySecurityCommunity;
  }
  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr )
    throws SAXException {
    writerReset();
    if (log.isDebugEnabled()) {
      log.debug("startElement: " + localName);
    }
    String currentRole = attr.getValue("role");
    String currentSecurityCommunity = attr.getValue("securitycommunity");

    if (( (currentRole != null) && (!currentRole.equals(role)) ) ||
	( (currentSecurityCommunity != null) && (!currentSecurityCommunity.equals(mySecurityCommunity)) )) {
      endElementAction = SKIP;
    }
    else if (currentRole == null || currentSecurityCommunity == null) {
      endElementAction = SET_DEFAULT;
    }
    else {
      // Both role and communit information match
      endElementAction = SET_VALUE;
    }
  }
 
  public void endElement( String namespaceURI,
			  String localName,
			  String qName )
    throws SAXException {
    if (log.isDebugEnabled()) {
      log.debug("endElement: " + localName
		+ " - qName: " + qName
		+ " - namespaceURI: " + namespaceURI);
    }
    if (localName.equals(topLevelTag) && parent != null) {
      // swap content handler back to parent
      if (log.isDebugEnabled()) {
	log.debug("Swapping to content handler back to parent");
      }
      writerReset();
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
    return (contentsValue == null ? null : contentsValue.trim());
  }

  private String contentsValue;

  protected void setContents() {
    contentsValue = parseContents(contents.toString());
  }

  protected String parseContents(String s) {
    if (log.isDebugEnabled()) {
      log.debug("Entering parseContents with " + s);
      log.debug("String = "+ s);
    }
    Pattern p_javaprop = Pattern.compile("\\$\\{.*\\}");
    Pattern p_keyvalue = Pattern.compile("\\$\\|.*\\|");
    //  The following was the old setting but it doesn't work with the 
    //  new xerces because $[distinguishedName]  is read by the parser as 
    //  two tokens, $[distinguishedName and ].
    //    Pattern p_keyvalue = Pattern.compile("\\$\\[.*\\]");
    Matcher matcher = null;
    StringBuffer sb = new StringBuffer();
    boolean result = false;


    if (replaceJavaProperties) {
      if (log.isDebugEnabled()) {
        log.debug("Looking up java property pattern in " + s);
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
        if (log.isDebugEnabled()) {
          log.debug("Replacing " + token + " with " + propertyValue);
        }
	matcher.appendReplacement(sb, propertyValue);
	result = matcher.find();
      }
      // Add the last segment of input to 
      // the new String
      matcher.appendTail(sb);
      s = sb.toString();
    }

    if (attributeTable != null && replaceAttributes) {
      if (log.isDebugEnabled()) {
	log.debug("Looking up attribute pattern in " + s);
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
        if (log.isDebugEnabled()) {
          log.debug("Replacing " + token + " with " + attributeValue);
        }
	matcher.appendReplacement(sb, attributeValue);
	result = matcher.find();
      }
      // Add the last segment of input to 
      // the new String
      matcher.appendTail(sb);
      s = sb.toString();
    }
    if (log.isDebugEnabled()) {
      log.debug("Returning " + s);
    }
    return s;
  }

 
  /** Receive notification of a notation declaration event.
   */
  public void notationDecl(String name, String publicId, String systemId) {
    if (log.isDebugEnabled()) {
      log.debug("Name: " + name + " publicId: " + publicId
		+ " systemId: " + systemId);
    }
  }

  /** Receive notification of an unparsed entity declaration event.
   */
  public void unparsedEntityDecl(String name, String publicId,
				 String systemId, String notationName) {
    if (log.isDebugEnabled()) {
      log.debug("Name: " + name + " publicId: " + publicId
		+ " notationName: " + notationName);
    }
  }

  /** Allow the application to resolve external entities.
   */
  public InputSource resolveEntity(String publicId, String systemId) {
    InputSource is = null;
    if (log.isDebugEnabled()) {
      log.debug(" publicId: " + publicId
		+ " systemId: " + systemId);
    }
    return is;
  }

}
