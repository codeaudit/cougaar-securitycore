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

public class NodeConfiguration
  implements Serializable
{
  /** The top-level directory of the securityservices module. */
  private String topLevelDirectory;

  /** The startup directory for the node. */
  private String nodeDirectoryName;

  /** The file containing the java properties for the node. */
  private String propertyFile;

  /** The name of the experiment */
  private String experimentName;

  /** The command-line arguments when starting the node. */
  private String nodeArguments[];

  /** Additional VM properties. */
  private Properties properties;

  /** The host name where the node is executed. */
  private String hostName;

  /** The maximum amount of time (in seconds) during which the node can run. */
  private int maxExecutionTime;

  /** The waiting period (in seconds) before the node is executed. */
  private int howLongBeforeStart;

  /** The HTTP port number of the node's web server. */
  private int httpPort;

  /** The HTTPS port number of the node's web server. */
  private int httpsPort;

  /** The RMI registry port number of the node's server. */
  private int rmiRegistryPort;

  /** A description of what the node is doing */
  private String nodeDescription;
  private OperationConf preOperation;
  private OperationConf postOperation;

  /** The name of the node. */
  private String nodeName;

  //////////////////////////////////////////////////////
  // Node results
  private int errors;
  private int failures;
  private double completionTime;
  private Date startTime;
  private Date analyzisDate;
  private String logFilesUrls;
  private SerializableTestResult testResult;

  /** The directory where results are stored. */
  private String resultPath;
  private String log4jLogFile;

  public NodeConfiguration() {
    properties = new Properties();
  }

  ///////////////////////////////////////////////////////
  // Configuration GET methods
  public String getNodeDescription() {
    return nodeDescription;
  }

  public OperationConf getPreOperation() {
    return preOperation;
  }

  public OperationConf getPostOperation() {
    return postOperation;
  }

  public String getTopLevelDirectory() {
    return topLevelDirectory;
  }
  public String getNodeStartupDirectoryName() {
    return nodeDirectoryName;
  }
  public String getPropertyFile() {
    return propertyFile;
  }
  public Properties getAdditionalVmProperties() {
    return properties;
  }
  public String[] getNodeArguments() {
    return nodeArguments;
  }
  public int getMaxExecutionTime() {
    return maxExecutionTime;
  }
  public int getHowLongBeforeStart() {
    return howLongBeforeStart;
  }
  public String getHostName() {
    return hostName;
  }
  public String getNodeName() {
    return nodeName;
  }
  public int getHttpPort() {
    return httpPort;
  }
  public int getHttpsPort() {
    return httpsPort;
  }
  public int getRmiRegistryPort() {
    return rmiRegistryPort;
  }
  public String getExperimentName() {
    return experimentName;
  }

  ///////////////////////////////////////////////////////
  // Results GET methods
  public int getErrors() {
    return errors;
  }
  public int getFailures() {
    return failures;
  }
  public double getCompletionTime() {
    return completionTime;
  }
  public Date getStartTime() {
    return startTime;
  }
  public Date getAnalyzisDate() {
    return analyzisDate;
  }
  private String makeLink(String path, String name) {
    String link = "";
    try {
      link = path;
      if (!link.startsWith("/")) {
	link = "/" + link;
      }
      link = "." + link;
      File f = new File(path);
      link = "<a href=\"" + link + "\">" + name + "</a>";
    }
    catch (Exception e) {}
    return link;
  }

  /** Should be called after the experiment to setup the links to the log files
   *  and the status of the file (non existent, empty...)
   */
  public void setLogFilesUrls() {
    String s = "";
    s = s +          makeLink("NODE-" + getNodeName() + "-out.log");
    s = s + "<br>" + makeLink("NODE-" + getNodeName() + "-err.log");
    s = s + "<br>" + makeLink("log4j.html");
    logFilesUrls = s;
  }

  private String makeLink(String fileName) {
    String link = "";
    try {
      link = "results/" + experimentName + "/" + getNodeName() + "/" + fileName;
      File fileURL = new File(link);
      link = makeLink(link, fileURL.getName());

      String f = topLevelDirectory + File.separator
	+ "regress" + File.separator + "results" + File.separator + experimentName + File.separator
	+ getNodeName() + File.separator + fileName;
      System.out.println("Checking status of " + f);
      File file = new File(f);
      if (!file.exists()) {
	link = link + " (missing)";
      }
      else {
	link = link + " (size=" + file.length() + ")";
      }
    }
    catch (Exception e) {}
    return link;
  }

  public String getLogFilesUrls() {
    return logFilesUrls;
  }
  public SerializableTestResult getTestResult() {
    return testResult;
  }

  public String getResultPath() {
    return resultPath;
  }
  public String getLog4jLogFile() {
    return log4jLogFile;
  }

  //////////////////////////////////////////////////////
  // Configuration SET methods
  public void setPreOperation(OperationConf oc) {
    preOperation = oc;
  }
  public void setPostOperation(OperationConf oc) {
    postOperation = oc;
  }
  public void setTopLevelDirectory(String dir) {
    topLevelDirectory = dir;
  }
  public void setExperimentName(String name) {
    experimentName = name;
  }
  public void setNodeStartupDirectoryName(String dir) {
    nodeDirectoryName = dir;
  }
  public void setPropertyFile(String file) {
    propertyFile = file;
  }
  public void addAdditionalVmProperties(String key, String value) {
    properties.put(key, value);
  }
  public void setNodeArguments(String args[]) {
    nodeArguments = args;
  }
  public void setNodeName(String name) {
    nodeName = name;
  }
  public void setNodeDescription(String desc) {
    nodeDescription = desc;
  }
  public void setMaxExecutionTime(int max) {
    maxExecutionTime = max;
  }
  public void setHowLongBeforeStart(int howlong) {
    howLongBeforeStart = howlong;
  }
  public void setHostName(String host) {
    hostName = host;
  }
  public void setHttpPort(int port) {
    httpPort = port;
  }
  public void setHttpsPort(int port) {
    httpsPort = port;
  }
  public void setRmiRegistryPort(int port) {
    rmiRegistryPort = port;
  }

  ///////////////////////////////////////////////////////
  // Results SET methods
  public void setErrors(int err) {
    errors = err;
  }
  public void setFailures(int f) {
    failures = f;
  }
  public void setCompletionTime(double ct) {
    completionTime = ct;
  }
  public void setStartTime(Date st) {
    startTime = st;
  }
  public void setAnalyzisDate(Date st) {
    analyzisDate = st;
  }
  public void setTestResult(SerializableTestResult tr) {
    testResult = tr;
  }
  public void setResultPath(String path) {
    resultPath = path;
  }
  public void setLog4jLogFile(String path) {
    log4jLogFile = path;
  }

  ///////////////////////////////////////////////////////
  public String toString() {
    String s =
      " Node Name: " + nodeName +
      "\n Node Description: " + nodeDescription +
      "\n Top-level directory: " + topLevelDirectory +
      "\n nodeDirectoryName: " + nodeDirectoryName +
      "\n propertyFile: " + propertyFile +
      "\n Additional properties: \n";
    Enumeration e = properties.propertyNames();
    while (e.hasMoreElements()) {
      String key = (String) e.nextElement();
      String value = properties.getProperty(key);
      s = s + "   " + key + "=" + value + '\n';
    }

    s = s +  " Node arguments: ";
    if (nodeArguments != null) {
      for (int i = 0 ; i < nodeArguments.length ; i++) {
	s = s + nodeArguments[i].toString() + " ";
      }
    }
    s = s +
      "\n hostName: " + hostName +
      "\n maxExecutionTime: " + maxExecutionTime +
      "\n howLongBeforeStart: " + howLongBeforeStart +
      "\n httpPort: " + httpPort +
      "\n httpsPort: " + httpsPort +
      "\n rmiRegistryPort: " + rmiRegistryPort + 
      "\n" + (preOperation == null ? "No pre operation" : preOperation.toString())
      + "\n" + (postOperation == null ? "No post operation" : postOperation.toString()) + "\n";

    // Results
    s = s + "==== Results =======\n";
    s = s + "Errors: " + errors + '\n';
    s = s + "Failures: " + failures + '\n';
    s = s + "completion Time: " + completionTime + '\n';
    s = s + "start Time: " + startTime + '\n';
    s = s + "log Files Urls: " + getLogFilesUrls() + '\n';

    return s;
  }
}
