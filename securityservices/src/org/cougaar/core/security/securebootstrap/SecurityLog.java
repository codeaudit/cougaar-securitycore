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

package org.cougaar.core.security.securebootstrap;

import java.io.*;
import java.util.*;
import java.text.*;

public class SecurityLog 
  implements Runnable
{
  private PrintStream log;
  private int loudness;
  private EventHolder eventholder=null;
  private String type=null;

  public SecurityLog(int loudness)
  {
    this.loudness = loudness;
    this.type=BootstrapEvent.JarVerificationAlarm;
    eventholder=EventHolder.getInstance();
  }
  public void createLogFile(String nodeName) {

    // Get name of the log file
    String sep =  System.getProperty("file.separator", "/");
    // Since multiple nodes may run on the same machine, we need
    // to make sure two nodes will not write to the same log file.
    // Also, log files should not be overwritten each time a
    // node is started again (for forensic purposes).
    Calendar rightNow = Calendar.getInstance();
    String curTime = rightNow.get(Calendar.YEAR) + "-" +
      rightNow.get(Calendar.MONTH) + "-" +
      rightNow.get(Calendar.DAY_OF_MONTH) + "-" +
      rightNow.get(Calendar.HOUR_OF_DAY) + "-" +
      rightNow.get(Calendar.MINUTE);

    String defaultLogName =
      System.getProperty("org.cougaar.install.path", "") +
      sep + "log" + sep + "bootstrap" + sep + "JarVerification_"
      + nodeName + "_" + curTime + ".log";
    String logname =
      System.getProperty("org.cougaar.core.security.bootstrap.JarVerificationLogFile",
			 defaultLogName);

    if (loudness > 0) {
      System.out.println("Creating Jar Verification Log " + logname);
    }

    try {
      log = new PrintStream(new FileOutputStream(logname));
      log.print("<logtime>"+DateFormat.getDateInstance().format(new Date())+"</logtime>\n");
      log.print("<nodeName>"+nodeName+"</nodeName>\n");
    }
    catch (IOException e) {
      System.err.println("Jar verification log file not opened properly\n" + e.toString());
    }
  }
  
  /** Logs exceptions of type java.security.GeneralSecurityException and 
   *    java.lang.SecurityException 
   */
  public  void logJarVerificationError (Exception e) {
    /* Could be used to report jar file verification exceptions
     * to a Monitoring & Response Plugin. */
    if (log != null) {
      String curTime = DateFormat.getDateInstance().format(new Date());
      log.print("<securityEvent><time>" + curTime + "</time>");
      log.print(e.getMessage());
      log.print("\n<stack>\n");
      e.printStackTrace(log);
      log.print("</stack></securityEvent>\n");
      ByteArrayOutputStream outstream=new ByteArrayOutputStream();
      e.printStackTrace(new PrintStream(outstream));
      eventholder.addEvent(new BootstrapEvent(type,Calendar.getInstance().getTime(),
						      null,outstream.toString()));
    }
    else if (loudness > 0) {
      System.out.println("Unable to log JAR file verification error:" + e);
    }
  }
  public void run() {

  }
}




