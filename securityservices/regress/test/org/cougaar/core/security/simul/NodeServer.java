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
import java.rmi.Naming;
import java.rmi.RMISecurityManager;
import java.rmi.registry.LocateRegistry;

public class NodeServer
  extends java.rmi.server.UnicastRemoteObject
  implements RemoteControl
{
  private int rmiRegistryPort;

  /** Environment variables when launching a node. */
  private String environmentVariables[];
  private ArrayList properties;

  private String javaBin;
  private String mainClassName;

  private String cip;
  private String hostName;
  private String nodeName;
  private String userName;

  private String commandLine;
  private File nodeStartupDirectory;
  private String resultPath;
  private String junitConfigPath;

  public NodeServer()
    throws java.rmi.RemoteException {
    super();
    properties = new ArrayList();
  }

  public void killServer()
    throws java.rmi.RemoteException {
    Runtime.getRuntime().exit(0);
  }

  public void startNode(NodeConfiguration tcc)
    throws java.rmi.RemoteException {

    System.out.println("NodeServer.startNode");
    String args[] = tcc.getNodeArguments();
    nodeName = args[0];

    resultPath = System.getProperty("junit.test.result.path");
    System.out.println("Result path: " + resultPath);
    Assert.assertNotNull("Unable to get test output path. Set junit.test.result.path",
			 resultPath);

    nodeStartupDirectory = new File(tcc.getNodeStartupDirectoryName());
    if (!nodeStartupDirectory.exists() || !nodeStartupDirectory.isDirectory()) {
      Assert.fail("Unable to go to " + nodeStartupDirectory.getPath());
    }

    userName = System.getProperty("user.name");
    Assert.assertNotNull("Unable to get user name", userName);

    cip = System.getProperty("org.cougaar.install.path");
    Assert.assertNotNull("Unable to get COUGAAR_INSTALL_PATH", cip);

    junitConfigPath = System.getProperty("org.cougaar.junit.config.path");
    Assert.assertNotNull("Unable to get org.cougaar.junit.config.path", junitConfigPath);

    try {
      hostName = InetAddress.getLocalHost().getHostName();
    }
    catch (Exception e) {
      Assert.fail("Unable to get host name: " + e);
      return;
    }

    File f = findPropertiesFile(tcc.getPropertyFile());
    readPropertiesFile(f, tcc);

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
      System.out.println("Node will be forcible killed in "
			 + tcc.getMaxExecutionTime() + " seconds.");
      NodeTimeoutController ntc =
	new NodeTimeoutController(nodeApp, tcc.getMaxExecutionTime());
      ntc.start();

      ProcessGobbler pg = new ProcessGobbler(resultPath, nodeName, nodeApp);
      pg.dumpProcessStream();

      PrintWriter outWriter = new PrintWriter(nodeApp.getOutputStream(), true);
      outWriter.println("cd " + nodeStartupDirectory.getAbsoluteFile());
      outWriter.println(commandLine);
      outWriter.flush();

      // any error???
      System.out.println("Waiting for node to exit");
      int exitVal = nodeApp.waitFor();
      System.out.println("ExitValue: " + exitVal); 

      // Wait for the threads to die
      //nodeAppOut.join();
      //nodeAppErr.join();

      if (pg.getErrStreamGobbler().getWrittenBytes() > 0) {
	// There was an error
	Assert.fail("The node wrote " +
			  pg.getErrStreamGobbler().getWrittenBytes() + " bytes to STDERR");
      }

      pg.getExperimentOutLog().close();
      pg.getExperimentErrLog().close();
      //nodeApp.getInputStream().close();
      //nodeApp.getErrorStream().close();

    }
    catch (Exception e) {
      e.printStackTrace();
      Assert.fail("Unable to start node: " + e);
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

  private void readPropertiesFile(File f, NodeConfiguration tcc) {
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
	  propertyValue = customizeProperty(st.nextToken(), tcc);
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
      Assert.fail("User parameter configuration file not found");
    }
    catch(IOException ioexp) {
      Assert.fail("Cannot read User parameter configuration file: " + ioexp);
    }
    environmentVariables = (String[])env.toArray(new String[0]);
  }

  private String customizeProperty(String propertyValue, NodeConfiguration tcc) {
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
      Integer.toString(tcc.getHttpPort()),
      Integer.toString(tcc.getHttpsPort()),
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

  public static void main (String args[]) {
    // Create and install a security manager
    if (System.getSecurityManager() == null) {
      System.setSecurityManager(new RMISecurityManager());
    }

    int rmiRegistryPort =
      Integer.valueOf(args[0]).intValue();

    // Create the RMI objects

    try {
      NodeServer obj = new NodeServer();

      obj.createRMIRegistry(rmiRegistryPort);

      // Bind this object instance to the name "HelloServer"
      String hostName = null;
      try {
	hostName = InetAddress.getLocalHost().getHostName();
      }
      catch (Exception e) {
	Assert.fail("Unable to get host name: " + e);
	return;
      }
      Naming.rebind("//" + hostName + ":" + rmiRegistryPort + "/NodeServer", obj);
	
      System.out.println("NodeServer bound in registry");
    } catch (Exception e) {
      System.out.println("NodeImpl err: " + e.getMessage());
      e.printStackTrace();
    }
  }

  /** Create an RMI registry.
   */
  private void createRMIRegistry(int rmiport)
    throws java.rmi.RemoteException {
    rmiRegistryPort = rmiport;
    LocateRegistry.createRegistry(rmiRegistryPort);
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
}
