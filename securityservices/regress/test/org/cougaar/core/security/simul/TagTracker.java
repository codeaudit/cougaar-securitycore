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

import java.util.*;
import java.io.*;
import org.xml.sax.*;


public class TagTracker {

  // Table of tag trackers.
  // This table contains an entry for
  // every tag name that this TagTracker
  // has been configured to follow.
  // This is a single-level parent-child relation.
  //
  private Hashtable trackers = new Hashtable();

  // Useful for skipping tag names that are not
  // being tracked.
  private static SkippingTagTracker skip = new SkippingTagTracker();

  // default constructor
  public TagTracker() {}


  // Configuration method for setting up a network
  // of tag trackers...
  // Each parent tag name should be configured
  // ( call this method ) for each child tag name
  // that it will track.
  public void track( String tagName, TagTracker tracker ){


    int slashOffset = tagName.indexOf( "/" );

    if( slashOffset < 0 ) {
      // if it is a simple tag name ( no "/" separators )
      // simply add it.
      SaxMapperLog.trace( "Adding tracker for " + tagName + "]");
      trackers.put( tagName, tracker);

    } else if ( slashOffset == 0 ) {
      // Oooops leading slash, remove it and
      // try again recursively.
      track( tagName.substring( 1 ), tracker );

    } else {
      // if it is not a simple tag name
      // recursively add the tag.
      String topTagName = tagName.substring( 0, slashOffset );
      String remainderOfTagName = tagName.substring( slashOffset + 1 );
      TagTracker child = (TagTracker)trackers.get( topTagName );
      if ( child == null ) {
	// Not currently tracking this
	// tag. Add new tracker.
	child = new TagTracker();
	SaxMapperLog.trace( "Adding tracker for " + topTagName + "]");
	trackers.put( topTagName, child );
      }
      child.track( remainderOfTagName, tracker );

    }


  }


  // Tag trackers work together on a stack.
  // The tag tracker at the top of the stack
  // is the "active" tag tracker and is responsible
  // for delegating the tracking to a child tag
  // tracker or putting a skipping place marker on the
  // stack.
  //
  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr,
			    Stack tagStack ) {


    // Look up the tag name in the tracker table.
    // Note, this implementation does not address
    // using XML name space support that is now available
    // with SAX2.
    // We are simply using the localName as a key
    // to find a possible tracker.
    TagTracker tracker = (TagTracker) trackers.get( localName );

    //
    // Are we tracking this tag name?
    //
    if ( tracker == null ) {
      // Not tracking this
      // tag name.  Skip the
      // entire branch.
      SaxMapperLog.trace( "Skipping tag: [" + localName + "]");
      tagStack.push( skip );
    }
    else {

      // Found a tracker for this
      // tag name.  Make it the
      // new top of stack tag
      // tracker
      SaxMapperLog.trace( "Tracking tag: [" + localName + "]");

      // Send the deactivate event to this tracker.
      SaxMapperLog.trace( "Deactivating current tracker.");
      onDeactivate();

      // Send the on start to the new active
      // tracker.
      SaxMapperLog.trace( "Sending start event to [" + localName + "] tracker.");
      tracker.onStart(namespaceURI, localName,
		      qName, attr );
      tagStack.push( tracker );

    }

  }


  // Tag trackers work together on a stack.
  // The tag tracker at the top of the stack
  // is the "active" tag tracker and is responsible
  // for reestablishing its parent tag tracker
  // ( next to top of stack ) when it has
  // been notified of the closing tag.
  //
  public void endElement(   String namespaceURI,
			    String localName,
			    String qName,
			    CharArrayWriter contents,
			    Stack tagStack ) {


    // Send the end event.
    SaxMapperLog.trace( "Finished tracking tag: [" + localName + "]");
    onEnd( namespaceURI, localName, qName, contents );

    // Clean up the stack...
    tagStack.pop();

    // Send the reactivate event.
    TagTracker activeTracker = (TagTracker) tagStack.peek();
    if ( activeTracker != null ) {
      SaxMapperLog.trace( "Reactivating previous tag tracker.");
      activeTracker.onReactivate();
    }


  }


  // Methods for collecting content. These methods
  // are intended to be overridden with specific
  // actions for nodes in the tag tracking network
  // that require

  public void onStart( String namespaceURI,
		       String localName,
		       String qName,
		       Attributes attr ) {

    // default is no action...
  }

  public void onDeactivate() {

    // default is no action...
  }

  public void onEnd(   String namespaceURI,
		       String localName,
		       String qName,
		       CharArrayWriter contents ){

    // default is no action...
  }

  public void onReactivate() {

    // default is no action...
  }

}
