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

class SkippingTagTracker
  extends TagTracker
{
  // Tag trackers work together on a stack.
  // The tag tracker at the top of the stack
  // is the "active" tag tracker.
  //
  // This class represents a skipping place
  // marker on the stack.  When a real tag
  // tracker places a skipping tag tracker on
  // the stack, that is an indication that
  // all tag names found during the skip are
  // of no interest to the tag tracking network.
  //
  // This means that if the skipping tag tracker
  // is notified of a new tag name, this new
  // tag name should also be skipped.
  //
  // Since this class never varies its behavior,
  // it is OK for it to skip new tag names by
  // placing itself on the stack again.
  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr,
			    Stack tagStack ) {
    //
    // If the current tag name is being
    // skipped, all children should be
    // skipped.
    //
    SaxMapperLog.trace( "Skipping tag: [" + localName + "]");
    tagStack.push( this );

  }

  //
  // The skipping tag tracker has
  // nothing special to do when
  // a closing tag is found other
  // than to remove itself from
  // the stack, which as a side
  // effect replaces it with its
  // parent as the "active," top
  // of stack tag tracker.
  //
  public void endElement(   String namespaceURI,
			    String localName,
			    String qName,
			    CharArrayWriter contents,
			    Stack tagStack ) {

    // Clean up the stack...
    SaxMapperLog.trace( "Finished skipping tag: [" + localName + "]");
    tagStack.pop();

  }
}
