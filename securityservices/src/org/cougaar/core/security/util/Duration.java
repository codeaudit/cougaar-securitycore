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

package org.cougaar.core.security.util;

import java.util.StringTokenizer;

/** Helper class to handle certificate validity.
 * 
 */
public class Duration {
  /** The time span (in seconds) */
  private long duration;

  private final String symbol_year   = "y";
  private final String symbol_month  = "M";
  private final String symbol_day    = "d";
  private final String symbol_hour   = "h";
  private final String symbol_minute = "m";
  private final String symbol_second = "s";

  /** Parse a duration expressed in the following format:
   * <yyyy> y <MM> M <dd> d <hh> h <mm> m <ss> s
   * where at least one field must be provided. */
  public void parse(String text)
    throws NumberFormatException
  {
    StringTokenizer tokens = new StringTokenizer(text);

    long val = 0;
    boolean expectNumber = true;

    System.out.println("duration:" + text);

    while (tokens.hasMoreTokens()) {
      String s = tokens.nextToken();

      if (expectNumber) {
	// Try to find a number
	val = Long.decode(s).longValue();
	expectNumber = false;
	// Will throw NumberFormatException if not a number
      }
      else {
	if (s.equals(symbol_year)) {
	  duration = duration + val * 365 * 86400;
	}
	else if (s.equals(symbol_month)) {
	  // It is assumed that the user does not really care about the exact duration.
	  duration = duration + val * (long)(30.5 * 86400);
	}
	else if (s.equals(symbol_day)) {
	  duration = duration + val * 86400;
	}
	else if (s.equals(symbol_hour)) {
	  duration = duration + val * 3600;
	}
	else if (s.equals(symbol_minute)) {
	  duration = duration + val * 60;
	}
	else if (s.equals(symbol_second)) {
	  duration = duration + val;
	}
	else {
	  throw new NumberFormatException("Expecting a symbol: " + s);
	}
	expectNumber = true;
      }
    }
     System.out.println("duration:" + duration);
  }

  public long getDuration()
  {
    return duration;
  }

  public static void main(String[] args) {
    Duration d = new Duration();
    d.parse(args[0]);
    System.out.println("Duration in seconds: " + d.getDuration());
  }
}
