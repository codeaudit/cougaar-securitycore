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

public class SummaryHandler
  extends DefaultHandler
{
  // XML Parser
  protected XMLReader parser;

  private String starttime;
  private String experimentname;

  // Buffer for collecting data from
  // the "characters" SAX event.
  protected CharArrayWriter contents = new CharArrayWriter();

  public SummaryHandler(XMLReader parser) {
    this.parser = parser;
  }

  public String getStartTime() {
    return starttime;
  }
  public String getExperimentName() {
    return experimentname;
  }

  public static final String EXPERIMENT = "experiment";

  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr )
    throws SAXException {
    contents.reset();

    System.out.println("localname:" + localName);
    if (localName.equals(EXPERIMENT)) {
      experimentname = attr.getValue("name");
      starttime = attr.getValue("starttime");
    }
  }

  public void characters( char[] ch, int start, int length )
    throws SAXException {
    contents.write(ch, start, length);
  }
}
