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
import java.net.*;
import java.util.*;
import java.text.*;
import java.rmi.Naming;
import java.rmi.RMISecurityManager;
import java.rmi.registry.LocateRegistry;

import junit.framework.*;
import org.apache.log4j.net.*;
import org.apache.log4j.LogManager;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.xml.DOMConfigurator;

public class NodeServer
  extends java.rmi.server.UnicastRemoteObject
  implements RemoteControl
{
  private static int rmiRegistryPort;
  private static int nextLog4jSocketPort = 11000;
  private Log4jSocketServer log4jSocketServer;

  public NodeServer()
    throws java.rmi.RemoteException {
    super();
    log4jSocketServer = new Log4jSocketServer();
  }

  public void killServer()
    throws java.rmi.RemoteException {
    Thread t = new RmiServerShutdownThread();
    t.start();
  }

  private class RmiServerShutdownThread extends Thread {
    // Need a clean solution to stop the RMI server,
    // but RMI launches non-daemon threads.
    // The Sleep() is to allow the client to receive the ACK
    public void run() {
      try {
	// Shutdown logger.
	LogManager.shutdown();
	Thread.sleep(2000);
      }
      catch (Exception e) {}
      Runtime.getRuntime().exit(0);
    }
  }

  public void startNode(NodeConfiguration tcc)
    throws java.rmi.RemoteException {

    String commandLine;
    File nodeStartupDirectory;
    String resultPath;
    PropertyFile propertyFile;

    System.out.println("NodeServer.startNode");
    String args[] = tcc.getNodeArguments();

    propertyFile = new PropertyFile();

    if (tcc.getNodeName() == null || tcc.getNodeName().equals("")) {
      return;
    }

    resultPath = System.getProperty("junit.test.result.path");
    System.out.println("Result path: " + resultPath);
    Assert.assertNotNull("Unable to get test output path. Set junit.test.result.path",
			 resultPath);

    nodeStartupDirectory = new File(tcc.getNodeStartupDirectoryName());
    if (!nodeStartupDirectory.exists() || !nodeStartupDirectory.isDirectory()) {
      Assert.fail("Unable to go to " + nodeStartupDirectory.getPath());
    }


    propertyFile.readPropertiesFile(tcc, nextLog4jSocketPort);

    // Start log4j SocketServer
    log4jSocketServer.startLog4jSocketServer(nextLog4jSocketPort, tcc);
    nextLog4jSocketPort++;

    // Construct command array
    propertyFile.getProperties().add(0, propertyFile.getJavaBin());
    // Add java properties

    propertyFile.getProperties().add(propertyFile.getMainClassName());

    // Add arguments
    for (int i = 0 ; i < args.length ; i++) {
      propertyFile.getProperties().add(args[i]);
    }
    String cmdArray[] = (String[]) propertyFile.getProperties().toArray(new String[0]);
    commandLine = "";
    System.out.println("+++ BEGIN Command line arguments");
    for (int i = 0 ; i < cmdArray.length ; i++) {
      commandLine = commandLine + cmdArray[i] + " ";
      System.out.println(cmdArray[i]);
    }
    System.out.println("+++ END Command line arguments");

    Runtime thisApp = Runtime.getRuntime();
    Process nodeApp = null;
    try {
      // Run Pre operation
      if (tcc.getPreOperation() != null) {
	tcc.getPreOperation().invokeMethod(null);
      }

      //System.out.println(commandLine);
      if (propertyFile.getEnvironmentVariables() != null) {
	for (int i = 0 ; i < propertyFile.getEnvironmentVariables().length ; i++) {
	  System.out.println(propertyFile.getEnvironmentVariables()[i]);
	}
      }
      System.out.println("Node startup directory: " + nodeStartupDirectory);

      nodeApp = thisApp.exec(cmdArray,
			     propertyFile.getEnvironmentVariables(),
			     nodeStartupDirectory);

     // Kill the node after n seconds
      System.out.println("Node will be forcible killed in "
			 + tcc.getMaxExecutionTime() + " seconds.");
      NodeTimeoutController ntc =
	new NodeTimeoutController(nodeApp, tcc);
      ntc.start();

      String nodeResultPath = NodeServerSuite.getCanonicalPath(resultPath + File.separator + tcc.getNodeName());
      ProcessGobbler pg = new ProcessGobbler(nodeResultPath, tcc.getNodeName(), nodeApp);
      pg.dumpProcessStream();

      // Write to process stdin
/*
      PrintWriter outWriter = new PrintWriter(nodeApp.getOutputStream(), true);
      outWriter.println("cd " + nodeStartupDirectory.getCanonicalFile());
      System.out.println("Executing: " + commandLine);
      outWriter.println(commandLine);
      outWriter.flush();
*/

      // any error???
      System.out.println("Waiting for node to exit");
      int exitVal = nodeApp.waitFor();
      System.out.println("ExitValue: " + exitVal); 

      if (pg.getErrStreamGobbler().getWrittenBytes() > 0) {
	// There was an error
	Assert.fail("The node wrote " +
			  pg.getErrStreamGobbler().getWrittenBytes() + " bytes to STDERR");
      }
      // Was there an error during the node cleanup?
      if (ntc.assertionFailure != null) {
	throw ntc.assertionFailure;
      }

      pg.getExperimentOutLog().close();
      pg.getExperimentErrLog().close();
      //nodeApp.getInputStream().close();
      //nodeApp.getErrorStream().close();

    }
    catch (Exception e) {
      e.printStackTrace();
      Assert.fail("RMI server unable to start node: " + e);
    }
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
    NodeConfiguration ncc;
    int maxExecutionTime;
    Error assertionFailure;

    public NodeTimeoutController(Process aNode, NodeConfiguration nc) {
      theNode = aNode;
      ncc = nc;
    }

    public void run() {
      try {
	Thread.sleep(ncc.getMaxExecutionTime() * 1000);
	System.out.println("Forcibly destroying node");
	theNode.destroy();
      
	// Run Post operation
	if (ncc.getPostOperation() != null) {
	  ncc.getPostOperation().invokeMethod(null);
	}
      }
      catch (Exception e) {
	e.printStackTrace();
	System.out.println("Error: " + e);
	assertionFailure =  new AssertionFailedError("Error during node cleanup: " + e);
      }
    }
  }

}
