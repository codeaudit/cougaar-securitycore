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
import java.util.regex.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import junit.framework.*;

import org.w3c.dom.*;

public class Experiment
  implements Serializable
{
  // Configuration
  private String experimentName;
  private String experimentDescription;
  private String junitResultLink;
  private Vector nodeConfList;
  private OperationConf preOperation;
  private OperationConf postOperation;
 
  // Results
  private Date analyzisDate;
  /** The date & time at which the experiment was started. */
  private Date startDate;
  private SerializableTestResult testResult;

  /** An array of files that contain the RMI server output. */
  private ArrayList rmiServerLogs;
  private String logFilesUrls; 

  public Experiment() {
    nodeConfList = new Vector();
    startDate = new Date();
    analyzisDate = new Date();
    rmiServerLogs = new ArrayList();
  }

  //////////////////////////////////////////////////////
  // GET methods
  public String getExperimentName() {
    return experimentName;
  }

  public String getExperimentDescription() {
    return experimentDescription;
  }

  public Vector getNodeConfiguration() {
    return nodeConfList;
  }

  public OperationConf getPreOperation() {
    return preOperation;
  }

  public OperationConf getPostOperation() {
    return postOperation;
  }

  public Date getStartDate() {
    return startDate;
  }

  //////////////////////////////////////////////////////
  // SET methods
  public void setExperimentName(String name) {
    experimentName = name;
  }
  public void setExperimentDescription(String desc) {
    experimentDescription = desc;
  }
    
  public void addNodeConfiguration(NodeConfiguration nc) {
    nodeConfList.addElement(nc);
  }

  public void setPreOperation(OperationConf oc) {
    preOperation = oc;
  }

  public void setPostOperation(OperationConf oc) {
    postOperation = oc;
  }

  ///////////////////////////////////////////////////////////////
  // Results GET methods
  public Date getAnalyzisDate() {
    return analyzisDate;
  }
  public SerializableTestResult getTestResult() {
    return testResult;
  }
  public String getJunitResultLink() {
    return junitResultLink;
  }

  ///////////////////////////////////////////////////////////////
  // Results SET methods
  public void setAnalyzisDate(Date date) {
    analyzisDate = date;
  }
  public void setTestResult(SerializableTestResult tr) {
    testResult = tr;
  }
  public void setJunitResultLink(String link) {
    junitResultLink = link;
  }
  public void addRmiServerLogFile(File f) {
    rmiServerLogs.add(f);
  }

  public String getLogFilesUrls() {
    String s = "";
    try {
      for (int i = 0 ; i < rmiServerLogs.size() ; i++) {
	File f = (File) rmiServerLogs.get(i);
        s = s + makeLink("results/" + experimentName
            + "/" + f.getName()) + "<br>";
      }
    }
    catch (Exception e) {}
    logFilesUrls = s;
    return logFilesUrls;
  }

  ///////////////////////////////////////////////////////////////

  private String makeLink(String path) {
    String link = "";
    try {
      link = path;
      if (!link.startsWith("/")) {
	link = "/" + link;
      }
      link = "." + link;
      File f = new File(path);
      link = "<a href=\"" + link + "\">" + f.getName() + "</a>";
    }
    catch (Exception e) {}
    return link;
  }

  public String toString() {
    String s = "Experiment name: " + experimentName + "\n";

    s = s + ( (preOperation == null) ? "None" : preOperation.toString()) + "\n";
    s = s + ( (postOperation == null) ? "None" : postOperation.toString()) + "\n";

    // Results
    s = s + "Start Date: " + startDate + " - Analyzis Date: " + analyzisDate + "\n";

    Enumeration e = nodeConfList.elements();
    int i = 0;
    while (e.hasMoreElements()) {
      NodeConfiguration nc = (NodeConfiguration) e.nextElement();
      s = s + "=====================\n" +
	"Node Configuration " + i + "\n"
	+ nc.toString();
      i++;
    }

    return s;
  }
}
