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

package org.cougaar.core.security.test;

import java.io.BufferedInputStream;
import java.io.File;

public class TestProcess
{
  private String environmentVariables[] = {
    "DISPLAY=localhost:0.0"
  };
  private File nodeStartupDirectory;
  //private String commandLine = "date";

  private String commandLine =
  "java -classpath /home/u/junittest/UL/cougaar/lib/securityservices.jar org.cougaar.core.security.test.TestProcess foo";

  public void start(String args[]) {
    Runtime thisApp = Runtime.getRuntime();
    Process nodeApp = null;
    nodeStartupDirectory = new File("./test/configs/cougaarCA");
    try {
      nodeApp = thisApp.exec(commandLine, null, nodeStartupDirectory);
      BufferedInputStream nodeAppOut = new BufferedInputStream(nodeApp.getInputStream());
      BufferedInputStream nodeAppErr = new BufferedInputStream(nodeApp.getErrorStream());

      Thread.sleep(3000);
      byte buffer[] = new byte[1000];
      int bytes = 0;
      while (bytes != -1) {
	bytes = nodeAppErr.read(buffer, 0, buffer.length);
	//System.out.println("StdErr: Reading " + bytes + " bytes");
	if (bytes > 0) {
	  String s = new String(buffer, 0, bytes);
	  System.err.print(s);
	}
      }

      bytes = 0;
      while (bytes != -1) {
	bytes = nodeAppOut.read(buffer, 0, buffer.length);
	//System.out.println("StdOut: Reading " + bytes + " bytes");
	if (bytes > 0) {
	  String s = new String(buffer, 0, bytes);
	  System.out.print(s);
	}
      }
      nodeAppOut.close();
      nodeAppErr.close();
      nodeApp.waitFor();
      System.out.println("Exit value: " + nodeApp.exitValue());
    }
    catch (Exception e) {
      e.printStackTrace();
      System.out.println("Exception: " + e);
    }
 }

  public static void main(String args[]) {
    System.out.println("Startup directory: " + System.getProperty("user.dir"));
    if (args.length == 0) {
      TestProcess tp = new TestProcess();
      tp.start(args);
    }
  }
}
