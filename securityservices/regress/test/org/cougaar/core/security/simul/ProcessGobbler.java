/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * Created on September 12, 2001, 10:55 AM
 */

package test.org.cougaar.core.security.simul;

import java.io.*;
import java.text.*;
import java.util.*;
import junit.framework.*;

public class ProcessGobbler
{
  private String experimentPath;
  private String nodeName;
  private Process nodeApp;

  private FileOutputStream experimentOutLog;
  private FileOutputStream experimentErrLog;

  private File experimentOutLogFile;
  private File experimentErrLogFile;

  private StreamGobbler nodeAppOut;
  private StreamGobbler nodeAppErr;

  public ProcessGobbler(String experimentPath, String nodeName, Process nodeApp) {
    this.experimentPath = experimentPath;
    this.nodeName = nodeName;
    this.nodeApp = nodeApp;
  }

  public void dumpProcessStream() {
    try {
      Date currentDate = new Date();
      SimpleDateFormat df = new SimpleDateFormat("yyyy.MM.dd-HH:mm:ss");
      experimentOutLogFile = new File(experimentPath + File.separator
				      + "NODE-" + nodeName 
				      + "-out.log");
      //+ "-" + df.format(currentDate) 
      experimentErrLogFile = new File(experimentPath + File.separator
				      + "NODE-" + nodeName 
				      + "-err.log");
      System.out.println("Node standard output file: "
			 + experimentOutLogFile.getPath());
      System.out.println("Node standard error file:  "
			 + experimentErrLogFile.getPath());
      experimentOutLogFile.createNewFile();
      experimentErrLogFile.createNewFile();

      experimentOutLog = new FileOutputStream(experimentOutLogFile);
      experimentErrLog = new FileOutputStream(experimentErrLogFile);

      nodeAppOut = new StreamGobbler(nodeApp.getInputStream(),
				     experimentOutLog, StreamGobbler.STDOUT);
      nodeAppErr = new StreamGobbler(nodeApp.getErrorStream(),
				     experimentErrLog, StreamGobbler.STDERR);
      nodeAppOut.start();
      nodeAppErr.start();
    }
    catch (Exception e) {
      ByteArrayOutputStream bo = new ByteArrayOutputStream();
      PrintStream ps = new PrintStream(bo);
      e.printStackTrace(ps);
      Assert.fail("Unable to log stdout/stderr: " + e + "\n"
	+ bo.toString() + "\nStdout log file: "
		  + experimentOutLogFile.getPath());
    }
  }

  public FileOutputStream getExperimentOutLog() {
    return experimentOutLog;
  }
  public FileOutputStream getExperimentErrLog() {
    return experimentErrLog;
  }

  public StreamGobbler getOutStreamGobbler() {
    return nodeAppOut;
  }
  public StreamGobbler getErrStreamGobbler() {
    return nodeAppErr;
  }

  public File getOutFile() {
    return experimentOutLogFile;
  }
  public File getErrFile() {
    return experimentErrLogFile;
  }
}
