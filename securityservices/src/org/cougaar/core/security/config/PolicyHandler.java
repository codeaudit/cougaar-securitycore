/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.config.jar.JarFileHandler;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.ConfigFinder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Hashtable;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

public class PolicyHandler
{
  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  protected static final String POLICIES_TAG = "policies";

  /** Default parser name. */
  protected static final String DEFAULT_PARSER_NAME =
  "org.apache.xerces.parsers.SAXParser";

  /** Lexical handler property id (http://xml.org/sax/properties/lexical-handler).
   */
  protected static final String LEXICAL_HANDLER_PROPERTY_ID =
  "http://xml.org/sax/properties/lexical-handler";

  public PolicyHandler(ConfigParserService configParser,
		       ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class,
			       null);
    this.configParser = configParser;
  }

  public void addCaPolicy(Hashtable attributeTable) {
    ConfigFinder confFinder = ConfigFinder.getInstance();
    InputStream xmlTemplateIs = null;
    try {
      xmlTemplateIs = confFinder.open("caPolicyTemplate.xml");
    }
    catch (IOException e) {
      if (log.isErrorEnabled()) {
        log.error("Unable to open caPolicyTemplate.xml: " + e);
      }
      return;
    }
    InputStream policyIs = configParser.findPolicyFile("cryptoPolicy.xml");

    // First, read the XML template
    ByteArrayOutputStream newPolicyOutputStream =
      parseXmlTemplate(xmlTemplateIs, attributeTable);

    if (log.isDebugEnabled()) {
      log.debug("NEW CA POLICY:");
      log.debug(newPolicyOutputStream.toString());
    }

    ConfigWriter writer = new ConfigWriter(serviceBroker);
    writer.replaceAttributes(false);
    writer.replaceJavaProperties(false);

    // Add the new policy
    writer.insertNodeAfterTag(POLICIES_TAG, newPolicyOutputStream);

    ByteArrayOutputStream newPolicy = new ByteArrayOutputStream();
    try {
      writer.setOutput(newPolicy, "US-ASCII");
    }
    catch (UnsupportedEncodingException e) {
      if (log.isErrorEnabled()) {
        log.error("Unable to set output.");
      }
      return;
    }
    if (log.isDebugEnabled()) {
      log.debug("Parsing policy file");
    }
    parseXmlFile(policyIs, writer);
    if (log.isDebugEnabled()) {
      log.debug("Parsing policy file done");
    }

    FileOutputStream newPolicyFile = null;

    // Add workspace/security/keystores/$nodeName directory to the search path
    String nodeName = secprop.getProperty("org.cougaar.node.name");
    String cougaarWsp=secprop.getProperty(SecurityPropertiesService.COUGAAR_WORKSPACE);
    String topDirectory = cougaarWsp + File.separatorChar + "security"
      + File.separatorChar + "keystores" + File.separatorChar;
    String nodeDirectory = topDirectory + nodeName;

    String fileName = null;
    String finderClass = System.getProperty(
      "org.cougaar.util.ConfigFinder.ClassName", null);
    File file = null;

    if (finderClass == null ||
      !finderClass.equals("org.cougaar.core.security.config.jar.SecureConfigFinder")) {
      fileName = nodeDirectory + File.separatorChar + "cryptoPolicy.xml";
      file = new File(fileName);
      try {
        newPolicyFile = new FileOutputStream(file);
        newPolicyFile.write(newPolicy.toByteArray());
      }
      catch (IOException e) {
        if  (log.isErrorEnabled()) {
          log.error("Unable to open policy file for modification");
        }
        return;
      }
    }
    else {
      // use jar file
      fileName = nodeDirectory + File.separatorChar + "policies.jar";
      file = new File(fileName);
      JarFileHandler jarHandler = JarFileHandler.getHandler(serviceBroker);
      jarHandler.updateJarFile("cryptoPolicy.xml", file, newPolicy);
    }

    // now read in the policy to ConfigParserService
    ByteArrayInputStream bis = new ByteArrayInputStream(newPolicyOutputStream.toByteArray());
    configParser.parsePolicy(bis);
  }

  public ByteArrayOutputStream parseXmlTemplate(InputStream xmlTemplateFile,
						Hashtable attributeTable) {

    ConfigWriter writer = new ConfigWriter(serviceBroker);
    writer.replaceAttributes(true);
    writer.replaceJavaProperties(true);
    writer.setAttributeTable(attributeTable);
    writer.setXmlHeader(false);

    ByteArrayOutputStream newPolicyOutputStream = new ByteArrayOutputStream();
    try {
      writer.setOutput(new DebugOutputStreamWrapper(newPolicyOutputStream),
                       "UTF8");
    }
    catch (UnsupportedEncodingException e) {
      System.err.println("error: Unable to set output.");
    }
    parseXmlFile(xmlTemplateFile, writer);

    return newPolicyOutputStream;
  }

  public void parseXmlFile(InputStream xmlTemplateFile,
			   ConfigWriter writer) {
    XMLReader parser = null;
    try {
      parser = XMLReaderFactory.createXMLReader(DEFAULT_PARSER_NAME);
    }
    catch (Exception e) {
      System.err.println("error: Unable to instantiate parser ("+DEFAULT_PARSER_NAME+")");
    }
    // set parser
    parser.setContentHandler(writer);
    parser.setErrorHandler(writer);
    try {
      parser.setProperty(LEXICAL_HANDLER_PROPERTY_ID, writer);
    }
    catch (SAXException e) {
      // Strange that this isn't an error to at least be logged??
      if (log.isDebugEnabled()) {
        log.debug("Exception setting lexical handler", e);
      }
    }

    try {
      if (log.isDebugEnabled()) {
        log.debug("start parsing xml file");
      }
      parser.parse(new InputSource(xmlTemplateFile));
      if (log.isDebugEnabled()) {
        log.debug("done parsing xml file");
      }
    }
    catch (SAXParseException e) {
      // Strange that this isn't at least logged as error?
      if (log.isDebugEnabled()) {
        log.debug("Exception parsing file",  e);
      }
      // ignore
    }
    catch (Exception e) {
      System.err.println("error: Parse error occurred - "+e.getMessage());
      if (e instanceof SAXException) {
	e = ((SAXException)e).getException();
      }
      e.printStackTrace(System.err);
    }
  }

  private class DebugOutputStreamWrapper extends OutputStream
  {
    OutputStream stream;

    DebugOutputStreamWrapper(OutputStream o)
    {
      stream = o;
    }

    public void write(int b)
      throws IOException
    {
      if (log.isDebugEnabled()) {
        char out = (char) b;
        log.debug("DebugOutputWrapper = " + out);
      }
      stream.write(b);
    }
  }

}

