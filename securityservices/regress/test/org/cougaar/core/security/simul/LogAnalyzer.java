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

package test.org.cougaar.core.security.simul;

import java.io.*;
import java.util.*;
import junit.framework.*;

public class LogAnalyzer
{
  private ArrayList failureStrings;
  private ArrayList mandatoryStrings;
  private File logFile;

  public LogAnalyzer() {
  }

  /** Add a string that should not be in the log. */
  public void addFailureString(String s, int count) {
    LogStringCondition cond = new LogStringCondition(s, count);
    failureStrings.add(cond);
  }

  /** Add a string that must be in the log.
   *  @param s the string that must occur in the log file
   *  @param count the number of times the string must appear in the log
   */
  public void addMandatoryString(String s, int count) {
    LogStringCondition cond = new LogStringCondition(s, count);
    mandatoryStrings.add(cond);
  }

  public void setLogFile(String log) {
    logFile = new File(log);
  }

  public void analyzeLog() {
    try {
      FileReader filereader=new FileReader(logFile);
      BufferedReader buffreader=new BufferedReader(filereader);
      String linedata=new String();

      Iterator mIt = mandatoryStrings.iterator();

      while((linedata=buffreader.readLine())!=null) {
	while (mIt.hasNext()) {
	  LogStringCondition lsc = (LogStringCondition) mIt.next();
	  if (linedata.indexOf(lsc.theString) != -1) {
	    lsc.actualCount++;
	  }
	}
      }
    }
    catch (Exception e) {
      Assert.fail("Failed analyzing log file: " + e);
    }
  }
}
