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

import junit.framework.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.text.*;

public class NodeServer
{
  private int httpPort;
  private int httpsPort;

  /** Environment variables when launching a node. */
  private String environmentVariables[];
  private ArrayList properties;

  private String javaBin;
  private String mainClassName;

  private String cip;
  private String userName;
  private String hostName;
  private String nodeName;

  private String commandLine;
  private File nodeStartupDirectory;
  private String testOutputPath;
  private String junitConfigPath;

  public NodeServer() {
    properties = new ArrayList();
  }

  public void startNode(String args[], String directoryName,
			String propertyFile, int maxExecutionTime) {
    nodeName = args[0];
    nodeStartupDirectory = new File(directoryName);
    if (!nodeStartupDirectory.exists() || !nodeStartupDirectory.isDirectory()) {
      Assert.assertTrue("Unable to go to " + nodeStartupDirectory.getPath(), false);
    }
    userName = System.getProperty("user.name");
    Assert.assertNotNull("Unable to get user name", userName);

    cip = System.getProperty("org.cougaar.install.path");
    Assert.assertNotNull("Unable to get COUGAAR_INSTALL_PATH", cip);

    junitConfigPath = System.getProperty("org.cougaar.junit.config.path");
    Assert.assertNotNull("Unable to get org.cougaar.junit.config.path", junitConfigPath);

    testOutputPath = System.getProperty("org.cougaar.junit.output.path");
    Assert.assertNotNull("Unable to get test output path. Set org.cougaar.junit.output.path",
			 testOutputPath);

    try {
      hostName = InetAddress.getLocalHost().getHostName();
    }
    catch (Exception e) {
      Assert.assertTrue("Unable to get host name: " + e, false);
      return;
    }

    setUserParameters();
    File f = findPropertiesFile(propertyFile);
    readPropertiesFile(f);

    commandLine = javaBin + " ";
    for (int i = 0 ; i < properties.size() ; i++) {
      commandLine = commandLine + properties.get(i) + " ";
    }
    commandLine = commandLine + " " + mainClassName
      + " org.cougaar.core.node.Node -n " + nodeName + " -c ";
    // Additional arguments
    for (int i = 1 ; i < args.length ; i++) {
      commandLine = commandLine + args[i] + " ";
    }
    Runtime thisApp = Runtime.getRuntime();
    Process nodeApp = null;
    try {
      //System.out.println(commandLine);
      for (int i = 0 ; i < environmentVariables.length ; i++) {
	System.out.println(environmentVariables[i]);
      }
      System.out.println("Node startup directory: " + nodeStartupDirectory.getAbsoluteFile());

      nodeApp = thisApp.exec("tcsh",
			     null, // environmentVariables
			     nodeStartupDirectory);

      // Kill the node after n seconds
      NodeTimeoutController ntc = new NodeTimeoutController(nodeApp, maxExecutionTime);
      ntc.start();

      Date currentDate = new Date();
      SimpleDateFormat df = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");
      File experimentLogFile = new File(testOutputPath + File.separator + "NODE-" + nodeName 
					+ " " + df.format(currentDate) + ".log");
      System.out.println("Node standard output file: " + experimentLogFile.getPath());
      experimentLogFile.createNewFile();
      FileOutputStream experimentLog = new FileOutputStream(experimentLogFile);

      PrintWriter outWriter = new PrintWriter(nodeApp.getOutputStream(), true);
      outWriter.println("cd " + nodeStartupDirectory.getAbsoluteFile());
      outWriter.println(commandLine);
      outWriter.flush();

      StreamGobbler nodeAppOut = new StreamGobbler(nodeApp.getInputStream(), experimentLog, STDOUT);
      StreamGobbler nodeAppErr = new StreamGobbler(nodeApp.getErrorStream(), experimentLog, STDERR);

      nodeAppOut.start();
      nodeAppErr.start();

      // any error???
      int exitVal = nodeApp.waitFor();
      System.out.println("ExitValue: " + exitVal); 

      // Wait for the threads to die
      //nodeAppOut.join();
      //nodeAppErr.join();

      if (nodeAppErr.getWrittenBytes() > 0) {
	// There was an error
	Assert.assertTrue("The node wrote " +
			  nodeAppErr.getWrittenBytes() + " bytes to STDERR", false);
      }

      experimentLog.close();
      //nodeApp.getInputStream().close();
      //nodeApp.getErrorStream().close();

    }
    catch (Exception e) {
      e.printStackTrace();
      Assert.assertTrue("Unable to start node: " + e, false);
    }
  }

  private void setUserParameters() {
    File userParamFile = new File(junitConfigPath + File.separator + "userParameters.conf");
    if (!userParamFile.exists()) {
      throw new RuntimeException("Unable to find user parameter configuration file");
    }
    try {
      FileReader filereader=new FileReader(userParamFile);
      BufferedReader buffreader=new BufferedReader(filereader);
      String linedata=new String();

      // Set default values
      httpPort = 8800;
      httpsPort = 9800;

      while((linedata=buffreader.readLine())!=null) {
	linedata.trim();
	if(linedata.startsWith("#")) {
	  continue;
	}
	StringTokenizer st = new StringTokenizer(linedata, ",");
	if (!st.hasMoreTokens()) {
	  // Empty line. Continue
	  continue;
	}
	String aUserName = st.nextToken();
	if (userName.equals(aUserName)) {
	  // Get HTTP port number
	  if (!st.hasMoreTokens()) {
	    throw new RuntimeException("Incorrect configuration file. Expected HTTP port number");
	  }
	  httpPort = Integer.valueOf(st.nextToken()).intValue();
	  // Get HTTPS port number
	  if (!st.hasMoreTokens()) {
	    throw new RuntimeException("Incorrect configuration file. Expected HTTPS port number");
	  }
	  httpsPort = Integer.valueOf(st.nextToken()).intValue();
	}
      }
    }
    catch(FileNotFoundException fnotfoundexp) {
      Assert.assertTrue("User parameter configuration file not found", false);
      fnotfoundexp.printStackTrace();
    }
    catch(IOException ioexp) {
      Assert.assertTrue("Cannot read User parameter configuration file: " + ioexp, false);
      ioexp.printStackTrace();
    }
  }

  private File findPropertiesFile(String propertyFile) {
    File f = null;
    f = new File(propertyFile);
    if (!f.exists()) {
      f = null;
    }
    if (f == null) {
      f = new File("Linux.props");
      if (!f.exists()) {
	f = null;
      }
    }
    if (f == null) {
      f = new File(cip + File.separator + "configs"
		   + File.separator + "security" 
		   + File.separator + "Linux.props");
      System.out.println("Trying " + f.getPath() + "...");
      if (!f.exists()) {
	f = null;
      }
    }
    Assert.assertNotNull("Unable to find properties file", f);
    return f;
  }

  private void readPropertiesFile(File f) {
    ArrayList env = new ArrayList();
    try {
      FileReader filereader=new FileReader(f);
      BufferedReader buffreader=new BufferedReader(filereader);
      String linedata=new String();

      // Default values
      javaBin = "java";
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
	  propertyValue = customizeProperty(st.nextToken());
	}

	if (property.startsWith("env.")) {
	  // Environment variable
	  property = property.substring(4);
	  String ev = property + "=" + propertyValue;
	  env.add(ev);
	}
	else if (property.equals("java.jvm.program")) {
	  javaBin = propertyValue;
	}
	else if (property.equals("java.class.name")) {
	  mainClassName = propertyValue;
	}
	else {
	  properties.add(makeProperty(property, propertyValue));
	}
      }
    }
    catch(FileNotFoundException fnotfoundexp) {
      Assert.assertTrue("User parameter configuration file not found", false);
    }
    catch(IOException ioexp) {
      Assert.assertTrue("Cannot read User parameter configuration file: " + ioexp, false);
    }
    environmentVariables = (String[])env.toArray(new String[0]);
  }

  private String customizeProperty(String propertyValue) {
    String convertFrom[] = {
      "/mnt/shared/integ92",
      "asmt",
      "5557",
      "6557",
      "\\$HOSTNAME.log",
      "\\$HOSTNAME"
      };

    String convertTo[] = {
      cip,
      userName,
      Integer.toString(httpPort),
      Integer.toString(httpsPort),
      nodeName + ".log",
      hostName
    };

    for (int i = 0 ; i < convertFrom.length ; i++) {
      propertyValue = propertyValue.replaceAll(convertFrom[i], convertTo[i]);
    }
    return propertyValue;
  }

  private String makeProperty(String propertyName, String propertyValue) {
    String argument = null;

    String convertFlagsFrom[] = {
      "java.jar",
      "java.class.path"
    };
    String convertFlagsTo[] = {
      "jar",
      "classpath"
    };

    String convertEqualsFrom[] = {
      "java.heap.min",
      "java.heap.max",
      "java.stack.size"
    };
    String convertEqualsTo[] = {
      "Xms",
      "Xmx",
      "Xss"
    };

    String convertCPFrom[] = {
      "java.Xbootclasspath",
      "java.Xbootclasspath/a",
      "java.Xbootclasspath/p"
    };
    String convertCPTo[] = {
      "Xbootclasspath",
      "Xbootclasspath/a",
      "Xbootclasspath/p"
    };

    if (propertyName.startsWith("java.")) {
      boolean isConverted = false;
      for (int i = 0 ; i < convertFlagsFrom.length ; i++) {
	if (propertyName.equals(convertFlagsFrom[i])) {
	  propertyName = convertFlagsTo[i];
	  argument = "-" + propertyName + " " + propertyValue;
	  isConverted = true;
	  break;
	}
      }
      if (!isConverted) {
	for (int i = 0 ; i < convertEqualsFrom.length ; i++) {
	  if (propertyName.equals(convertEqualsFrom[i])) {
	    propertyName = convertEqualsTo[i];
	    argument = "-" + propertyName + "=" + propertyValue;
	    isConverted = true;
	    break;
	  }
	}
      }
      if (!isConverted) {
	for (int i = 0 ; i < convertCPFrom.length ; i++) {
	  if (propertyName.equals(convertCPFrom[i])) {
	    propertyName = convertCPTo[i];
	    argument = "-" + propertyName + ":" + propertyValue;
	    isConverted = true;
	    break;
	  }
	}
      }

      if (!isConverted) {
	if (propertyName.equals("java.jvm.mode")) {
	  if (propertyValue.equals("client") ||
	      propertyValue.equals("server")) {
	    argument = "-" + propertyValue;
	    isConverted = true;
	  }
	}
      }

      if (!isConverted) {
	propertyName = propertyName.substring("java.".length());
	if (propertyValue != null) {
	  argument = "-" + propertyName + "=" + propertyValue;
	}
	else {
	  argument = "-" + propertyName;
	}
	isConverted = true;
      }
    }
    else {
      argument = "-D" + propertyName + "=" + propertyValue;
    }
    return argument;
  }

  private class NodeTimeoutController
    extends Thread
  {
    Process theNode;
    int maxExecutionTime;

    public NodeTimeoutController(Process aNode, int maxtime) {
      theNode = aNode;
      maxExecutionTime = maxtime;
    }

    public void run() {
      try {
	Thread.sleep(maxExecutionTime * 1000);
      }
      catch (Exception e) {
	System.out.println("Error: " + e);
      }
      System.out.println("Forcibly destroying node");
      theNode.destroy();
    }
  }

  public static int STDERR = 1;
  public static int STDOUT = 2;

  private class StreamGobbler
    extends Thread
  {
    private InputStream is;
    private OutputStream os;
    private int bytesWritten;

    StreamGobbler(InputStream is, OutputStream os, int streamType) {
      this.is = is;
      this.os = os;
    }

    public int getWrittenBytes() {
      return bytesWritten;
    }

    public void run() {
      try {
	byte buffer[] = new byte[2000];
	int bytes = 0;
	BufferedInputStream bir = new BufferedInputStream(is);
	//InputStream bir = is;

	while (bytes != -1) {
	  bytes = bir.read(buffer, 0, buffer.length);
	  if (bytes > 0) {
	    os.write(buffer, 0, bytes);
	    os.flush();
	    bytesWritten += bytes;
	  }
	}
      }
      catch (IOException ioe) {
	ioe.printStackTrace();  
      }
    }
  }
}
