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

public class Dashboard
{
  static private String analyzisDate;
  static private String experimentName;
  static private int errors;
  static private int failures;
  static private int numberOfTests;
  static private int completionTime;

  static String files[];

  static {
    files =  new String[1];
    files[0] = "/home/u/junittest/UL/securityservices/regress/result.xml";
    numberOfTests = files.length;
  }

  public static ResultHandler parseExperimentResults(String fileName) {
    ResultParser rp = new ResultParser(fileName);
    rp.parseResults();
    return rp.getResultHandler();
  }

  public static void analyzeResults(int i) {
    ResultHandler rp = null;

    System.out.println("Parsing file: " + files[i]);
    rp = parseExperimentResults(files[i]);
    errors = rp.getErrors();
    failures = rp.getFailures();
    experimentName = rp.getName();
    completionTime = rp.getCompletionTime();
  }

  public static String getAnalyzisDate() {
    return analyzisDate;
  }

  public static int getNumberOfTests() {
    return numberOfTests;
  }

  public static String getExperimentName() {
    return experimentName;
  }

  public static int getErrors() {
    return errors;
  }

  public static int getFailures() {
    return failures;
  }

}
