/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.util;

import java.util.StringTokenizer;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

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
  private LoggingService log;

  public Duration(ServiceBroker sb) {
    log = (LoggingService)
      sb.getService(this,
		    LoggingService.class, null);
  }

  /** Parse a duration expressed in the following format:
   * <yyyy> y <MM> M <dd> d <hh> h <mm> m <ss> s
   * where at least one field must be provided. */
  public void parse(String text)
    throws NumberFormatException
  {
    StringTokenizer tokens = new StringTokenizer(text);

    long val = 0;
    boolean expectNumber = true;

    log.debug("duration:" + text);

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
    log.debug("duration:" + duration);
  }

  public long getDuration()
  {
    return duration;
  }

}
