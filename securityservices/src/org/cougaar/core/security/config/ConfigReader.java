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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import java.io.FileReader;

import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

public class ConfigReader
{
  // XML Parser
  private XMLReader parser;
  private LoggingService log;
  private ServiceBroker serviceBroker;

  public ConfigReader(ServiceBroker sb) {
    serviceBroker = sb;
    this.log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    try {
      // Create SAX 2 parser...
      parser = XMLReaderFactory.createXMLReader();
    }
    catch ( Exception e ) {
      e.printStackTrace();
    }
  }

  public void parsePolicy(String filePath, String role, String community) {
    try {
      // Set the ContentHandler...
      ConfigParserHandler handler = new ConfigParserHandler(parser, role, serviceBroker, community);
      parser.setContentHandler(handler);

      // Parse the file...
      parser.parse( new InputSource(new FileReader(filePath)) );
    }
    catch ( Exception e ) {
      e.printStackTrace();
    }
  }
}
