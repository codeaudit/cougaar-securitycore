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

import test.org.cougaar.core.security.simul.*;

public class Dashboard
{
  /** The number of experiments. */
  private int experimentCount;
  /** The list of directories containing experiment results. */
  private File[] subdirectories;
  private boolean analyzisDone = false;
  private Date analyzisDate;

  /** A vector of experiments */
  static private Vector experiments;
  private URL propFileUrl;

  static private Dashboard singleton;

  protected Dashboard() {
    experiments = new Vector();
  }

  public static Dashboard getInstance() {
    // Implement a singleton class
    if (singleton == null) {
      singleton = new Dashboard();
    }
    return singleton;
  }

  static public void main(String args[]) {
    Dashboard dashboard = Dashboard.getInstance();
    dashboard.analyzeResults();

    System.out.println("Number of experiments: "
		       + dashboard.getExperimentCount());
    for (int i = 0 ; i < dashboard.getExperimentCount() ; i++) {
      System.out.println("=========== Experiment " + i + " ==============");
      Experiment exp = (Experiment) experiments.get(i);
      System.out.println(exp.toString());
    }
  }

  public void analyzeResults() {
    if (analyzisDone == true) {
      return;
    }

    analyzisDate = new Date();

    subdirectories = getDirectories();
    if (subdirectories != null) {
      analyzeExperiments();
      experimentCount = experiments.size();
      //resultFiles = getResultFiles("results.xml", "summary.xml");
    }
    System.out.println("Number of experiments: " + experimentCount);

/*
    if (resultFiles != null) {
      experimentResults = new ExperimentResults[resultFiles.length];
      for (int i = 0 ; i < resultFiles.length ; i++) {
	System.out.println("Parsing file [" + (i+1) + "/" + resultFiles.length + "]: " + resultFiles[i].resultFile);
	ResultParser res = parseExperimentResults(resultFiles[i]);
	ResultHandler rp = res.getResultHandler();
	SummaryHandler sh = res.getSummaryHandler();

	experimentResults[i] = new ExperimentResults();

	experimentResults[i].logFilesUrls = getLogFileUrls(subdirectories[i], ".log");
	experimentResults[i].resultLogFilesUrls = getLogFileUrls(subdirectories[i], "results.xml");
	if (rp != null) {
	  experimentResults[i].errors = rp.getErrors();
	  experimentResults[i].failures = rp.getFailures();
	  experimentResults[i].completionTime = rp.getCompletionTime();
	}
	if (sh != null) {
	  experimentResults[i].experimentName = sh.getExperimentName();
	  experimentResults[i].startTime = sh.getStartTime();
	}
      }
    }
*/
    analyzisDone = true;
  }

/*
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
*/

  public File[] getDirectories() {
    readPropertyFile();
    String dir = System.getProperty("org.cougaar.core.security.jsp.path");
    System.out.println("Results directory:" + dir);

    File resultsDirectory = null;
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

  private void analyzeExperiments() {
    for (int i = 0 ; i < subdirectories.length ; i++) {
      File f = new File(subdirectories[i], "experiment.dat");
      experiments.add(loadExperiment(f));
    }
    Comparator comparator = new Comparator() {
	public int compare(Object o1, Object o2) {
	  Experiment e1 = (Experiment) o1;
	  Experiment e2 = (Experiment) o2;
	  return (e1.getStartDate().compareTo(e2.getStartDate()));
	}
      };
    Collections.sort(experiments, comparator);
  }

  private Experiment loadExperiment(File f) {
    Experiment exp = null;
    try {
      FileInputStream fi = new FileInputStream(f);
      ObjectInputStream is = new ObjectInputStream(fi);
      Object o = is.readObject();
      exp = (Experiment) o;
      is.close();
    }
    catch (Exception e) {
      System.out.println("Unable to load experiment:" + e);
      e.printStackTrace();
    }
    return exp;
  }

/*
  private static File[] getFilesWithSuffix(File directory, final String suffix) {
    File resFiles[] = null;
    ArrayList fileList = new ArrayList();
    File[] rfile = null;
    rfile = directory.listFiles(
      new FileFilter() {
	public boolean accept(File f) {
	  if (f == null) {
	    return false;
	  }
	  return f.getName().endsWith(suffix);
	}
      });
    if (rfile != null) {
      for (int j = 0 ; j < rfile.length ; j++) {
	fileList.add(rfile[j]);
      }
    }
    resFiles = (File[]) fileList.toArray(new File[0]);
    return resFiles;
   }

  public static ResultFiles[] getResultFiles(final String resultFileSuffix, final String summaryFileSuffix) {
    ResultFiles resFiles[] = null;
    if (subdirectories == null) {
      subdirectories = getDirectories();
    }
    if (subdirectories != null) {
      ArrayList fileList = new ArrayList();
      for (int i = 0 ; i < subdirectories.length ; i++) {
	ResultFiles rf = null;
	File[] rfile = getFilesWithSuffix(subdirectories[i], resultFileSuffix);
	if (rfile != null) {
	  if (rfile.length > 1) {
	    // There should be only one result file
	    throw new RuntimeException("There should be at most one result file. Found " + rfile.length
	      + " files");
	  }
	  rf = new ResultFiles();
	  if (rfile.length == 1) {
	    rf.resultFile = rfile[0];
	  }
	}
	File[] sfile = getFilesWithSuffix(subdirectories[i], summaryFileSuffix);
	if (sfile != null) {
	  if (sfile.length > 1) {
	    // There should be only one result file
	    throw new RuntimeException("There should be at most one summary file. Found " + sfile.length
	      + " files");
	  }
	  if (rf == null) {
	    rf = new ResultFiles();
	  }
	  if (sfile.length == 1) {
	    rf.summaryFile = sfile[0];
	  }
	}
	if (rf != null) {
	  fileList.add(rf);
	}
      }
      resFiles = (ResultFiles[]) fileList.toArray(new ResultFiles[0]);
    }
    return resFiles;
  }

  public static ResultParser parseExperimentResults(ResultFiles resultFiles) {
    ResultParser rp = new ResultParser(resultFiles);
    rp.parseResults();
    rp.parseSummary();
    return rp;
  }

*/
  public int getExperimentCount() {
    if (analyzisDone == false) {
      analyzeResults();
    }
    return experimentCount;
  }

  public String getAnalyzisDate() {
    if (analyzisDone == false) {
      analyzeResults();
    }
    SimpleDateFormat df = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
    String theDate = df.format(analyzisDate);
    return theDate;
  }

  public Vector getExperiments() {
    return experiments;
  }

  public void setJavaPropURL(String url) {
    try {
      propFileUrl = new URL(url);
    }
    catch(Exception e) {
      System.out.println("Unable to parse URL: " + e);
      e.printStackTrace();
    }
  }

  private void readPropertyFile() {
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
