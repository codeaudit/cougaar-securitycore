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
import java.text.*;
import java.util.regex.*;
import junit.framework.*;
import java.rmi.Naming;
import java.rmi.registry.*;

public class NodeServerTest
  extends TestCase
{
  private NodeConfiguration nodeConf;
  private ArrayList threadList;
  private TestResult nodeTestResult;
  /** The top-level directory of the experiment. */
  private String resultPath;

  public NodeServerTest(String name) {
    super(name);

    resultPath = System.getProperty("junit.test.result.path");
    System.out.println("Result path: " + resultPath);
    Assert.assertNotNull("Unable to get test output path. Set junit.test.result.path",
			 resultPath);
    resultPath = NodeServerSuite.getCanonicalPath(resultPath);
    System.out.println("Result path: " + resultPath);

  }

  public void setNodeConfiguration(NodeConfiguration tcc) {
    if (tcc == null) {
      throw new IllegalArgumentException("NodeConfiguration is null");
    }
    nodeConf = tcc;
  }
  public void setThreadList(ArrayList tl) {
    if (tl == null) {
      throw new IllegalArgumentException("Thread list is null");
    }
    threadList = tl;
  }

  /**
   * Creates a default TestResult object
   *
   * @see TestResult
   */
  protected TestResult createResult() {
    System.out.println("Creating new SerializableTestResult for Node");
    return new SerializableTestResult();
  }
  
  /**
   * Runs the test case and collects the results in TestResult.
   */
  public void run(TestResult result) {
    System.out.println("Starting node test...");
    nodeTestResult = result;
    nodeTestResult.startTest(this);
    Protectable p = new ThreadedProtectable(this);
    nodeTestResult.runProtected(this, p);
    nodeTestResult.endTest(this);
    System.out.println("End node test...");
  }

  public void setUp() {
  }

  public void testRunNode() {
    //saveExperimentInfo(tcc);
    try {
      System.out.println("Waiting " + nodeConf.getHowLongBeforeStart() + "s...");
      Thread.sleep(1000 * nodeConf.getHowLongBeforeStart());
      threadList.add(runRemoteNode(nodeConf));
    }
    catch (Exception e) {
      e.printStackTrace();
      Assert.fail("Unable to execute remote node: " + e);
    }
  }

  private Thread runRemoteNode(NodeConfiguration tcc) {
    String nodeResultPath = resultPath + File.separator + tcc.getNodeName();
    try {
      File f = new File(nodeResultPath);
      System.out.println("Creating output directory: " + nodeResultPath);
      f.mkdir();
    } catch (Exception e) { 
      e.printStackTrace();
      Assert.fail("Unable to create output directory: " + nodeResultPath);
    }

    RemoteNode rn = new RemoteNode(tcc, nodeTestResult, this);
    rn.start();
    return rn;
  }

  private class RemoteNode
    extends Thread
  {
    private NodeConfiguration tcc;
    private TestResult testResult;
    private Test test;

    public RemoteNode(NodeConfiguration nc, TestResult testResult, Test test) {
      if (testResult == null) {
	throw new IllegalArgumentException("testResult is null");
      }
      if (test == null) {
	throw new IllegalArgumentException("test is null");
      }
      this.tcc = nc;
      this.testResult = testResult;
      this.test = test;
    }

    /**
     * Execute a remote node.
     * The following processes are started and shut down in the following sequence:
     * 1) This NodeServerTest application is started through the ant script.
     * 2) The NodeServerTest app starts a local process which executes a remote RMI server through ssh.
     * 3) An RMI server is started on the remote machine
     * 4) The RMI server starts the node on the remote machine
     * 5) When the remote node terminates, the RMI server is also terminated
     * 6) The local ssh process terminates
     * 7) This NodeServerTest application terminates
     */
    public void run() {
      RemoteControl nodeServer = null;
      
      try {
	nodeServer = getRemoteControl();

	System.out.println("Calling startNode on remote server");
	nodeServer.startNode(tcc);

      } catch (Exception e) { 
	e.printStackTrace();
	testResult.addFailure(test, new AssertionFailedError("RMI request startNode() failed: " + e));
      } catch (AssertionFailedError e) {
	testResult.addFailure(test, e);
      }
    }

    private RemoteControl getRemoteControl() {
      RemoteControl nodeServer = null;

      try {
	Registry registry = LocateRegistry.getRegistry(tcc.getHostName(), tcc.getRmiRegistryPort());
	String list[] = registry.list();
	System.out.println("Registered objects in " + tcc.getHostName() + " registry: ");
	for (int i = 0 ; i < list.length ; i++) {
	  System.out.println(list[i]);
	}
	nodeServer = (RemoteControl)registry.lookup("NodeServer");
	Assert.assertNotNull("Could not create Remote NodeServer", nodeServer);
      }
      catch (Exception e) {
	System.out.println("Unable to get remote control server");
	Assert.fail("Unable to get remote control server: " + e);
      }
      return nodeServer;
    }
  }
}
