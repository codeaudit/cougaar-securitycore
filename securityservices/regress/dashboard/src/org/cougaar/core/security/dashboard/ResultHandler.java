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

package org.cougaar.core.security.dashboard;

import java.io.*;
import java.util.*;

import org.xml.sax.*;
import org.xml.sax.helpers.*;

public class ResultHandler
  extends DefaultHandler
{
  // XML Parser
  protected XMLReader parser;

  private int errors;
  private int failures;
  private int completionTime;
  private String name;

  // Buffer for collecting data from
  // the "characters" SAX event.
  protected CharArrayWriter contents = new CharArrayWriter();

  public ResultHandler(XMLReader parser) {
    this.parser = parser;
  }

  public int getErrors() {
    return errors;
  }
  public int getFailures() {
    return errors;
  }
  public int getCompletionTime() {
    return completionTime;
  }
  public String getName() {
    return name;
  }

  public static final String TEST_SUITE = "testsuite";

  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr )
    throws SAXException {
    contents.reset();

    if (localName.equals(TEST_SUITE)) {
      errors = Integer.valueOf(attr.getValue("errors")).intValue();
      failures = Integer.valueOf(attr.getValue("failures")).intValue();
      name = attr.getValue("name");
      completionTime = Integer.valueOf(attr.getValue("time")).intValue();
    }
  }

  public void characters( char[] ch, int start, int length )
    throws SAXException {
    contents.write(ch, start, length);
  }
}
