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


/*
 * The Apache Software License, Version 1.1
 *
 *
 * Copyright (c) 1999-2002 The Apache Software Foundation.  All rights 
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:  
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Xerces" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written 
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation and was
 * originally based on software copyright (c) 1999, International
 * Business Machines, Inc., http://www.apache.org.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */

package org.cougaar.core.security.config;

import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;
import org.xml.sax.ext.LexicalHandler;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.ParserAdapter;
import org.xml.sax.helpers.XMLReaderFactory;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

public class ConfigWriter
  extends BaseConfigHandler
  implements LexicalHandler
{
  //
  // Constants
  //

  // feature ids

    /** Namespaces feature id (http://xml.org/sax/features/namespaces).
     */
  protected static final String NAMESPACES_FEATURE_ID = "http://xml.org/sax/features/namespaces";

  /** Validation feature id (http://xml.org/sax/features/validation).
   */
  protected static final String VALIDATION_FEATURE_ID = "http://xml.org/sax/features/validation";

  /** Schema validation feature id (http://apache.org/xml/features/validation/schema).
   */
  protected static final String SCHEMA_VALIDATION_FEATURE_ID = "http://apache.org/xml/features/validation/schema";

  /** Schema full checking feature id (http://apache.org/xml/features/validation/schema-full-checking).
   */
  protected static final String SCHEMA_FULL_CHECKING_FEATURE_ID = "http://apache.org/xml/features/validation/schema-full-checking";

  // property ids

  /** Lexical handler property id (http://xml.org/sax/properties/lexical-handler).
   */
  protected static final String LEXICAL_HANDLER_PROPERTY_ID = "http://xml.org/sax/properties/lexical-handler";

  // default settings

  /** Default parser name.
   */
  protected static final String DEFAULT_PARSER_NAME = "org.apache.xerces.parsers.SAXParser";

  /** Default namespaces support (true).
   */
  protected static final boolean DEFAULT_NAMESPACES = true;

  /** Default validation support (false).
   */
  protected static final boolean DEFAULT_VALIDATION = false;

  /** Default Schema validation support (false).
   */
  protected static final boolean DEFAULT_SCHEMA_VALIDATION = false;

  /** Default Schema full checking support (false).
   */
  protected static final boolean DEFAULT_SCHEMA_FULL_CHECKING = false;

  /** Default canonical output (false).
   */
  protected static final boolean DEFAULT_CANONICAL = false;

  //
  // Data
  //

  /** Print writer.
   */
  protected PrintWriter fOut;

  /** Canonical output.
   */
  protected boolean fCanonical;

  /** Element depth.
   */
  protected int fElementDepth;

  protected boolean fXmlHeader = true;

  private String tagInsertionPoint;
  private ByteArrayOutputStream newNode;

  //
  // Constructors
  //

  /** Default constructor.
   */
  public ConfigWriter(ServiceBroker sb) {
    super(sb);
  } // <init>()

  //
  // Public methods
  //

  public void insertNodeAfterTag(String tag, ByteArrayOutputStream newNode) {
    tagInsertionPoint = tag;
    this.newNode = newNode;
  }

  /** Sets whether output is canonical. */
  public void setCanonical(boolean canonical) {
    fCanonical = canonical;
  } // setCanonical(boolean)

  /** Sets whether XML header is printed. */
  public void setXmlHeader(boolean xmlHeader) {
    fXmlHeader = xmlHeader;
  } // setXmlHeader(boolean)

  /** Gets the output stream
   */
  public PrintWriter getOutput() {
    return fOut;
  }

  /** Sets the output stream for printing.
   */
  public void setOutput(OutputStream stream, String encoding)
    throws UnsupportedEncodingException {

    if (encoding == null) {
      encoding = "US-ASCII";
    }

    java.io.Writer writer = new OutputStreamWriter(stream, encoding);
    fOut = new PrintWriter(writer);

  } // setOutput(OutputStream,String)

  /** Sets the output writer.
   */
  public void setOutput(java.io.Writer writer) {

    fOut = writer instanceof PrintWriter
      ? (PrintWriter)writer : new PrintWriter(writer);

  } // setOutput(java.io.Writer)

  //
  // ContentHandler methods
  //

  /** Start document.
   */
  public void startDocument() throws SAXException {

    fElementDepth = 0;

    if (!fCanonical && fXmlHeader) {
      fOut.println("<?xml version=\"1.0\" encoding=\"US-ASCII\"?>");
      fOut.flush();
    }

  } // startDocument()

  /** Processing instruction.
   */
  public void processingInstruction(String target, String data)
    throws SAXException {

    if (fElementDepth > 0) {
      fOut.print("<?");
      fOut.print(target);
      if (data != null && data.length() > 0) {
	fOut.print(' ');
	fOut.print(data);
      }
      fOut.print("?>");
      fOut.flush();
    }

  } // processingInstruction(String,String)

  /** Start element.
   */
  public void startElement(String uri, String local, String raw,
			   Attributes attrs) throws SAXException {
    fElementDepth++;
    fOut.print('<');
    fOut.print(raw);
    if (attrs != null) {
      attrs = sortAttributes(attrs);
      int len = attrs.getLength();
      for (int i = 0; i < len; i++) {
	fOut.print(' ');
	fOut.print(attrs.getQName(i));
	fOut.print("=\"");
	normalizeAndPrint(parseContents(attrs.getValue(i)));
	fOut.print('"');
      }
    }
    fOut.print('>');

    if (tagInsertionPoint != null) {
      if (local.equals(tagInsertionPoint)) {
	normalizeAndPrint('\n');
	fOut.print(newNode.toString());
      }
    }
    fOut.flush();

  } // startElement(String,String,String,Attributes)

  /** Characters.
   */
  public void characters(char ch[], int start, int length)
    throws SAXException {
    String s = new String(ch, start, length);
    normalizeAndPrint(parseContents(s));

  } // characters(char[],int,int);

  /** Ignorable whitespace.
   */
  public void ignorableWhitespace(char ch[], int start, int length)
    throws SAXException {

    characters(ch, start, length);
    fOut.flush();

  } // ignorableWhitespace(char[],int,int);

  /** End element.
   */
  public void endElement(String uri, String local, String raw)
    throws SAXException {
    fElementDepth--;
    fOut.print("</");
    fOut.print(parseContents(raw));
    fOut.print('>');
    fOut.flush();

  } // endElement(String)

  //
  // ErrorHandler methods
  //

  /** Warning.
   */
  public void warning(SAXParseException ex) throws SAXException {
    printError("Warning", ex);
  } // warning(SAXParseException)

  /** Error.
   */
  public void error(SAXParseException ex) throws SAXException {
    printError("Error", ex);
  } // error(SAXParseException)

  /** Fatal error.
   */
  public void fatalError(SAXParseException ex) throws SAXException {
    printError("Fatal Error", ex);
    ex.printStackTrace();
    throw ex;
  } // fatalError(SAXParseException)

  //
  // LexicalHandler methods
  //

  /** Start DTD.
   */
  public void startDTD(String name, String publicId, String systemId)
    throws SAXException {
  } // startDTD(String,String,String)

  /** End DTD.
   */
  public void endDTD() throws SAXException {
  } // endDTD()

  /** Start entity.
   */
  public void startEntity(String name) throws SAXException {
  } // startEntity(String)

  /** End entity.
   */
  public void endEntity(String name) throws SAXException {
  } // endEntity(String)

  /** Start CDATA section.
   */
  public void startCDATA() throws SAXException {
  } // startCDATA()

  /** End CDATA section.
   */
  public void endCDATA() throws SAXException {
  } // endCDATA()

  /** Comment.
   */
  public void comment(char ch[], int start, int length) throws SAXException {
    if (!fCanonical && fElementDepth > 0) {
      fOut.print("<!--");
      normalizeAndPrint(ch, start, length);
      fOut.print("-->");
      fOut.flush();
    }
  } // comment(char[],int,int)

  //
  // Protected methods
  //

    /** Returns a sorted list of attributes. */
  protected Attributes sortAttributes(Attributes attrs) {

    AttributesImpl attributes = new AttributesImpl();

    int len = (attrs != null) ? attrs.getLength() : 0;
    for (int i = 0; i < len; i++) {
      String name = attrs.getQName(i);
      int count = attributes.getLength();
      int j = 0;
      while (j < count) {
	if (name.compareTo(attributes.getQName(j)) < 0) {
	  break;
	}
	j++;
      }
      attributes.insertAttributeAt(j, name, attrs.getType(i),
				   attrs.getValue(i));
    }

    return attributes;

  } // sortAttributes(AttributeList):AttributeList

 
  /** Normalizes and prints the given string.
   */
  protected void normalizeAndPrint(String s) {

    int len = (s != null) ? s.length() : 0;
    for (int i = 0; i < len; i++) {
      char c = s.charAt(i);
      normalizeAndPrint(c);
    }

  } // normalizeAndPrint(String)

  /** Normalizes and prints the given array of characters. */
  protected void normalizeAndPrint(char[] ch, int offset, int length) {
    for (int i = 0; i < length; i++) {
      normalizeAndPrint(ch[offset + i]);
    }
  } // normalizeAndPrint(char[],int,int)

  /** Normalizes and print the given character.
   */
  protected void normalizeAndPrint(char c) {

    switch (c) {
    case '<': {
      fOut.print("&lt;");
      break;
    }
    case '>': {
      fOut.print("&gt;");
      break;
    }
    case '&': {
      fOut.print("&amp;");
      break;
    }
    case '"': {
      fOut.print("&quot;");
      break;
    }
    case '\r':
    case '\n': {
      if (fCanonical) {
	fOut.print("&#");
	fOut.print(Integer.toString(c));
	fOut.print(';');
	break;
      }
      // else, default print char
    }
    default: {
      fOut.print(c);
    }
    }

  } // normalizeAndPrint(char)

  /** Prints the error message.
   */
  protected void printError(String type, SAXParseException ex) {

    System.err.print("[");
    System.err.print(type);
    System.err.print("] ");
    String systemId = ex.getSystemId();
    if (systemId != null) {
      int index = systemId.lastIndexOf('/');
      if (index != -1)
	systemId = systemId.substring(index + 1);
      System.err.print(systemId);
    }
    System.err.print(':');
    System.err.print(ex.getLineNumber());
    System.err.print(':');
    System.err.print(ex.getColumnNumber());
    System.err.print(": ");
    System.err.print(ex.getMessage());
    System.err.println();
    System.err.flush();

  } // printError(String,SAXParseException)

  //
  // Main
  //

  /** Main program entry point.
   */
  public static void main(String argv[]) {

    // is there anything to do?
    if (argv.length == 0) {
      printUsage();
      return;
    }

    // variables
    ConfigWriter writer = null;
    XMLReader parser = null;
    boolean namespaces = DEFAULT_NAMESPACES;
    boolean validation = DEFAULT_VALIDATION;
    boolean schemaValidation = DEFAULT_SCHEMA_VALIDATION;
    boolean schemaFullChecking = DEFAULT_SCHEMA_FULL_CHECKING;
    boolean canonical = DEFAULT_CANONICAL;

    // process arguments
    for (int i = 0; i < argv.length; i++) {
      String arg = argv[i];
      if (arg.startsWith("-")) {
	String option = arg.substring(1);
	if (option.equals("p")) {
	  // get parser name
	  if (++i == argv.length) {
	    System.err.println("error: Missing argument to -p option.");
	  }
	  String parserName = argv[i];

	  // create parser
	  try {
	    parser = XMLReaderFactory.createXMLReader(parserName);
	  }
	  catch (Exception e) {
	    parser = null;
	    System.err.println("error: Unable to instantiate parser ("+parserName+")");
	  }
	  continue;
	}
	if (option.equalsIgnoreCase("n")) {
	  namespaces = option.equals("n");
	  continue;
	}
	if (option.equalsIgnoreCase("v")) {
	  validation = option.equals("v");
	  continue;
	}
	if (option.equalsIgnoreCase("s")) {
	  schemaValidation = option.equals("s");
	  continue;
	}
	if (option.equalsIgnoreCase("f")) {
	  schemaFullChecking = option.equals("f");
	  continue;
	}
	if (option.equalsIgnoreCase("c")) {
	  canonical = option.equals("c");
	  continue;
	}
	if (option.equals("h")) {
	  printUsage();
	  continue;
	}
      }

      // use default parser?
      if (parser == null) {

	// create parser
	try {
	  parser = XMLReaderFactory.createXMLReader(DEFAULT_PARSER_NAME);
	}
	catch (Exception e) {
	  System.err.println("error: Unable to instantiate parser ("+DEFAULT_PARSER_NAME+")");
	  continue;
	}
      }

      // set parser features
      try {
	parser.setFeature(NAMESPACES_FEATURE_ID, namespaces);
      }
      catch (SAXException e) {
	System.err.println("warning: Parser does not support feature ("+NAMESPACES_FEATURE_ID+")");
      }
      try {
	parser.setFeature(VALIDATION_FEATURE_ID, validation);
      }
      catch (SAXException e) {
	System.err.println("warning: Parser does not support feature ("+VALIDATION_FEATURE_ID+")");
      }
      try {
	parser.setFeature(SCHEMA_VALIDATION_FEATURE_ID, schemaValidation);
      }
      catch (SAXNotRecognizedException e) {
	// ignore
      }
      catch (SAXNotSupportedException e) {
	System.err.println("warning: Parser does not support feature ("+SCHEMA_VALIDATION_FEATURE_ID+")");
      }
      try {
	parser.setFeature(SCHEMA_FULL_CHECKING_FEATURE_ID, schemaFullChecking);
      }
      catch (SAXNotRecognizedException e) {
	// ignore
      }
      catch (SAXNotSupportedException e) {
	System.err.println("warning: Parser does not support feature ("+SCHEMA_FULL_CHECKING_FEATURE_ID+")");
      }

      // setup writer
      if (writer == null) {
	writer = new ConfigWriter(null);
	try {
	  writer.setOutput(System.out, "US-ASCII");
	}
	catch (UnsupportedEncodingException e) {
	  System.err.println("error: Unable to set output.");
	  return;
	}
      }

      // set parser
      parser.setContentHandler(writer);
      parser.setErrorHandler(writer);
      try {
	parser.setProperty(LEXICAL_HANDLER_PROPERTY_ID, writer);
      }
      catch (SAXException e) {
	// ignore
      }

      // parse file
      writer.setCanonical(canonical);
      try {
	parser.parse(arg);
      }
      catch (SAXParseException e) {
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

  } // main(String[])

  //
  // Private static methods
  //

  /** Prints the usage.
   */
  private static void printUsage() {

    System.err.println("usage: java sax.Writer (options) uri ...");
    System.err.println();

    System.err.println("options:");
    System.err.println("  -p name  Select parser by name.");
    System.err.println("  -n | -N  Turn on/off namespace processing.");
    System.err.println("  -v | -V  Turn on/off validation.");
    System.err.println("  -s | -S  Turn on/off Schema validation support.");
    System.err.println("           NOTE: Not supported by all parsers.");
    System.err.println("  -f  | -F Turn on/off Schema full checking.");
    System.err.println("           NOTE: Requires use of -s and not supported by all parsers.");
    System.err.println("  -c | -C  Turn on/off Canonical XML output.");
    System.err.println("           NOTE: This is not W3C canonical output.");
    System.err.println("  -h       This help screen.");
    System.err.println();

    System.err.println("defaults:");
    System.err.println("  Parser:     "+DEFAULT_PARSER_NAME);
    System.err.print("  Namespaces: ");
    System.err.println(DEFAULT_NAMESPACES ? "on" : "off");
    System.err.print("  Validation: ");
    System.err.println(DEFAULT_VALIDATION ? "on" : "off");
    System.err.print("  Schema:     ");
    System.err.println(DEFAULT_SCHEMA_VALIDATION ? "on" : "off");
    System.err.print("  Schema full checking:     ");
    System.err.println(DEFAULT_SCHEMA_FULL_CHECKING ? "on" : "off");
    System.err.print("  Canonical:  ");
    System.err.println(DEFAULT_CANONICAL ? "on" : "off");

  } // printUsage()
  
} // class Writer
