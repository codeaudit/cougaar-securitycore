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
 * Code from " Mapping XML to Java, Part 2" By Robert Hustead
 * http://www.javaworld.com/javaworld/jw-10-2000/jw-1006-sax.html
 *
 * CHANGE RECORD
 * - 
 */

package test.org.cougaar.core.security.simul;

import java.io.*;
import java.util.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;

public abstract class SaxMapper
  extends DefaultHandler
{
  // Must be overridden by all subclasses...
  public abstract Object getMappedObject();
  public abstract TagTracker createTagTrackerNetwork();

  // A stack for the tag trackers to
  // coordinate on.
  //
  private Stack tagStack = new Stack();

  // The SAX 2 parser...
  private XMLReader xr;

  // Buffer for collecting data from
  // the "characters" SAX event.
  protected CharArrayWriter contents = new CharArrayWriter();

  public SaxMapper( ) {
    try {
      // Create the XML reader...
      xr = XMLReaderFactory.createXMLReader("org.apache.xerces.parsers.SAXParser");
    } catch ( Exception e ) {
      e.printStackTrace();
    }

    // Create the tag tracker network
    // and initialize the stack with
    // it.
    //
    // This constructor anchors the tag
    // tracking network to the beginning
    // of the XML document. ( before the
    // first tag name is located ).
    //
    // By placing it first on the stack
    // all future tag tracking will follow
    // the network anchored by this
    // root tag tracker.
    //
    // The createTagTrackerNetwork() method
    // is abstract.  All subclasses are
    // responsible for reacting to this
    // request with the creation of a
    // tag tracking network that will
    // perform the mapping for the subclass.
    //
    SaxMapperLog.trace( "Creating the tag tracker network." );
    tagStack.push( createTagTrackerNetwork() );
    SaxMapperLog.trace( "Tag tracker network created." );

  }

  public Object fromXML( String url ) {

    try {
      return fromXML( new InputSource( url ) );

    } catch ( Exception e ) {
      e.printStackTrace();
      return null;
    }
  }

  public Object fromXML( InputStream in ) {
    try {
      return fromXML( new InputSource( in ) );

    } catch ( Exception e ) {
      e.printStackTrace();
      return null;
    }
  }

  public Object fromXML( Reader in ) {
    try {
      return fromXML( new InputSource( in ) );

    } catch ( Exception e ) {
      e.printStackTrace();
      return null;
    }
  }

  private synchronized Object fromXML( InputSource in ) throws Exception {

    // notes,
    // 1.  The calling "fromXML" methods catch
    //     any parsing exceptions.
    // 2.  The method is synchronized to keep
    //     multiple threads from accessing the XML parser
    //     at once.  This is a limitation imposed by SAX.


    // Set the ContentHandler...
    xr.setContentHandler( this );


    // Parse the file...
    SaxMapperLog.trace( "About to parser XML document." );
    xr.parse( in );
    SaxMapperLog.trace( "XML document parsing complete." );

    return getMappedObject();
  }


  // Implement the content handler methods that
  // will delegate SAX events to the tag tracker network.

  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr ) throws SAXException {

    // Resetting contents buffer.
    // Assuming that tags either tag content or children, not both.
    // This is usually the case with XML that is representing
    // data structures in a programming language independent way.
    // This assumption is not typically valid where XML is being
    // used in the classical text mark up style where tagging
    // is used to style content and several styles may overlap
    // at once.
    contents.reset();

    // delegate the event handling to the tag tracker
    // network.
    TagTracker activeTracker = (TagTracker) tagStack.peek();
    activeTracker.startElement( namespaceURI, localName,
				qName, attr, tagStack );


  }

  public void endElement( String namespaceURI,
			  String localName,
			  String qName ) throws SAXException {

    // delegate the event handling to the tag tracker
    // network.
    TagTracker activeTracker = (TagTracker) tagStack.peek();
    activeTracker.endElement( namespaceURI, localName,
			      qName, contents, tagStack );

  }


  public void characters( char[] ch, int start, int length )
    throws SAXException {
    // accumulate the contents into a buffer.
    contents.write( ch, start, length );

  }
}
