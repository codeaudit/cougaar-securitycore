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
