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

public class SaxMapperLog {

  static boolean doTraceLogging =
  Boolean.getBoolean("test.org.cougaar.core.security.simul.SaxMapper.trace" );

  public static void trace( String msg ){

    if ( doTraceLogging )  {
      System.out.println( "trace: " + msg );
    }
  }

  public static void error(  String msg ){

    System.out.println( "error: " + msg );

  }


  // testing main method...
  public static void main( String[] argv ) {

    Boolean b = new Boolean( doTraceLogging );

    System.out.println( "Tracing is: ["
			+ b.toString()
			+ "]" );
    trace( "test message" );
  }
}
