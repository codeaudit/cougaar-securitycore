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
import java.net.*;
import java.text.*;

public class Dashboard
{
  static private int numberOfTests;
  static private File[] subdirectories;
  static private File resultFiles[];
  static private File summaryFiles[];
  static private File resultsDirectory;
  static private ExperimentResults experimentResults[];
  static private boolean analyzisDone = false;
  static private String analyzisDate;

  static public void main(String args[]) {
    System.out.println("Number of tests: " + getNumberOfTests());
    for (int i = 0 ; i < getNumberOfTests() ; i++) {
      System.out.println("Errors: " + getErrors(i));
      System.out.println("Failures: " + getFailures(i));
      System.out.println("Experiment Name: " + getExperimentName(i));
    }
  }

  static public void analyzeResults() {
    if (analyzisDone == true) {
      return;
    }

    Date currentDate = new Date();
    SimpleDateFormat df = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
    analyzisDate = df.format(currentDate);

    subdirectories = getDirectories();
    if (subdirectories != null) {
      numberOfTests = subdirectories.length;
      resultFiles = getResultFiles();
      summaryFiles = getSummaryFiles();
    }
    System.out.println("Number of directories to analyze: " + resultFiles.length);

    if (resultFiles != null) {
      experimentResults = new ExperimentResults[resultFiles.length];
      for (int i = 0 ; i < resultFiles.length ; i++) {
	System.out.println("Parsing file [" + (i+1) + "/" + resultFiles.length + "]: " + resultFiles[i]);
	ResultParser res = parseExperimentResults(resultFiles[i], summaryFiles[i]);
	ResultHandler rp = res.getResultHandler();
	SummaryHandler sh = res.getSummaryHandler();

	experimentResults[i] = new ExperimentResults();
	experimentResults[i].errors = rp.getErrors();
	experimentResults[i].failures = rp.getFailures();
	experimentResults[i].completionTime = rp.getCompletionTime();
	experimentResults[i].logFilesUrls = getLogFileUrls(subdirectories[i], ".log");
	experimentResults[i].resultLogFilesUrls = getLogFileUrls(subdirectories[i], "results.xml");

	experimentResults[i].experimentName = sh.getExperimentName();
	experimentResults[i].startTime = sh.getStartTime();
      }
    }
    analyzisDone = true;
  }

  private static String getLogFileUrls(File topDir, final String extension) {
    String url = "";
    if (topDir == null) {
      return url;
    }
    File subdir[] = null;
    if (topDir.exists()) {
      subdir = topDir.listFiles(
	new FileFilter() {
	  public boolean accept(File f) {
	    return (f.isFile() && f.getName().endsWith(extension));
	  }
	});
    }
    for (int i = 0 ; i < subdir.length ; i++) {
      url = url + "<a href=\"./results/" + topDir.getName() + "/" + subdir[i].getName()
	+ "\">" + subdir[i].getName() + "</a><br>";
    }
    return url;
  }

  public static File[] getDirectories() {
    readPropertyFile();
    String dir = System.getProperty("org.cougaar.core.security.jsp.path");
    System.out.println("Results directory:" + dir);

    if (dir != null) {
      resultsDirectory = new File(dir);
    }

    if (resultsDirectory == null) {
      return null;
    }
    File subdir[] = null;
    if (resultsDirectory.exists()) {
      subdir = resultsDirectory.listFiles(
	new FileFilter() {
	  public boolean accept(File f) {
	    return (f.isDirectory() && !f.getName().equals("html"));
	  }
	});
    }
    return subdir;
  }

  public static File[] getResultFiles() {
    File resFiles[] = null;
    if (subdirectories == null) {
      subdirectories = getDirectories();
    }
    if (subdirectories != null) {
      ArrayList fileList = new ArrayList();
      for (int i = 0 ; i < subdirectories.length ; i++) {
	File[] rfile = null;
	rfile = subdirectories[i].listFiles(
	  new FileFilter() {
	    public boolean accept(File f) {
	      if (f == null) {
		return false;
	      }
	      return f.getName().endsWith("results.xml");
	    }
	  });
	if (rfile != null) {
	  for (int j = 0 ; j < rfile.length ; j++) {
	    fileList.add(rfile[j]);
	  }
	}
      }
      resFiles = (File[]) fileList.toArray(new File[0]);
    }
    return resFiles;
  }

  public static File[] getSummaryFiles() {
    File resFiles[] = null;
    if (subdirectories == null) {
      subdirectories = getDirectories();
    }
    if (subdirectories != null) {
      ArrayList fileList = new ArrayList();
      for (int i = 0 ; i < subdirectories.length ; i++) {
	File[] rfile = null;
	rfile = subdirectories[i].listFiles(
	  new FileFilter() {
	    public boolean accept(File f) {
	      if (f == null) {
		return false;
	      }
	      return f.getName().endsWith("summary.xml");
	    }
	  });
	if (rfile != null) {
	  for (int j = 0 ; j < rfile.length ; j++) {
	    fileList.add(rfile[j]);
	  }
	}
      }
      resFiles = (File[]) fileList.toArray(new File[0]);
    }
    return resFiles;
  }

  public static ResultParser parseExperimentResults(File file, File summaryFile) {
    ResultParser rp = new ResultParser(file.getPath(), summaryFile.getPath());
    rp.parseResults();
    rp.parseSummary();
    return rp;
  }

  public static int getNumberOfTests() {
    if (analyzisDone == false) {
      analyzeResults();
    }
    return numberOfTests;
  }

  public static String getAnalyzisDate() {
    if (analyzisDone == false) {
      analyzeResults();
    }
    return analyzisDate;
  }

  public static String getStartTime(int i) {
    return experimentResults[i].startTime;
  }

  public static String getLogFileUrls(int i) {
    return experimentResults[i].logFilesUrls;
  }

  public static String getResultLogFileUrls(int i) {
    return experimentResults[i].resultLogFilesUrls;
  }

  public static String getAnalyzisDate(int i) {
    return experimentResults[i].analyzisDate;
  }

  public static String getExperimentName(int i) {
    return experimentResults[i].experimentName;
  }

  public static double getCompletionTime(int i) {
    return experimentResults[i].completionTime;
  }

  public static int getErrors(int i) {
    return experimentResults[i].errors;
  }

  public static int getFailures(int i) {
    return experimentResults[i].failures;
  }

  public static void setJavaPropURL(String url) {
    try {
      propFileUrl = new URL(url);
    }
    catch(Exception e) {
      System.out.println("Unable to parse URL: " + e);
      e.printStackTrace();
    }
  }
  private static URL propFileUrl;

  private static void readPropertyFile() {
    try {
      String file = propFileUrl.getFile();
      System.out.println("Path:" + propFileUrl.toString());
      URLConnection cn = propFileUrl.openConnection();
      InputStream is = cn.getInputStream();

      BufferedReader buffreader=new BufferedReader(new InputStreamReader(is));
      String linedata=new String();
      while((linedata=buffreader.readLine())!=null) {
	linedata.trim();
	if(linedata.startsWith("#")) {
	  continue;
	}
	StringTokenizer st = new StringTokenizer(linedata, "=");
	if (!st.hasMoreTokens()) {
	  // Empty line. Continue
	  continue;
	}
	String property = st.nextToken();
	String propertyValue = null;
	if (st.hasMoreTokens()) {
	  propertyValue = st.nextToken();
	}
	System.out.println("Setting " + property + "=" + propertyValue);
	System.setProperty(property, propertyValue);
      }
      is.close();
    }
    catch(Exception e) {
      System.out.println("Unable to read property file: " + e);
      e.printStackTrace();
    }
  }
}
