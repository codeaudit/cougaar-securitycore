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
import junit.framework.*;
import java.rmi.Naming;
import java.rmi.registry.*;

public class NodeServerTest
  extends TestCase
{
  /** A list of NodeConfiguration */
  private Vector nodeConfList;
  private String junitConfigPath;
  private String classPath;
  private String userDir;
  private String userName;
  private String resultPath;

  private TestResult testResult;
  private ConfigParser configParser;
  private ExperimentMapper experimentMapper;

  public NodeServerTest(String name) {
    super(name);
  }

  public void setUp() {
    junitConfigPath = System.getProperty("org.cougaar.junit.config.path");
    Assert.assertNotNull("Unable to get org.cougaar.junit.config.path", junitConfigPath);

    resultPath = System.getProperty("junit.test.result.path");
    Assert.assertNotNull("Unable to get test output path. Set junit.test.result.path",
			 resultPath);

    classPath = System.getProperty("org.cougaar.securityservices.classes");
    Assert.assertNotNull("Unable to get org.cougaar.securityservices.classes", classPath);

    userDir = System.getProperty("user.dir");
    Assert.assertNotNull("Unable to get user dir", userDir);

    userName = System.getProperty("user.name");
    Assert.assertNotNull("Unable to get user name", userName);

  }

  /**
   * Runs the test case and collects the results in TestResult.
   */
  public void run(TestResult result) {
    System.out.println("Starting test...");
    this.testResult = result;

    testResult.startTest(this);
    Protectable p = new ThreadedProtectable(this);
    testResult.runProtected(this, p);
    testResult.endTest(this);

    System.out.println("End test...");
  }


  public void testRunExperiment() {
    //readConfigurationFile();
    String fileName = System.getProperty("junit.config.file");
    //configParser = new ConfigParser(fileName);
    //configParser.parseNodeConfiguration();
    experimentMapper = new ExperimentMapper();
    Experiment experiment = (Experiment) experimentMapper.fromXML(fileName);

    nodeConfList = experiment.getNodeConfiguration();
    System.out.println(experiment.toString());

    // Run Pre operation
    try {
      experiment.getPreOperation().invokeMethod(null);
    }
    catch (Exception e) {
      Assert.fail("Unable to execute pre-operation:" + e);
    }
    //nodeConfList = configParser.getNodeConfigurationList();

    ArrayList threadList = new ArrayList();
    for (int i = 0 ; i < nodeConfList.size() ; i++) {
      NodeConfiguration tcc = (NodeConfiguration) nodeConfList.get(i);
      System.out.println("#####################################################");
      System.out.println("Test Case # " + i);
      System.out.print("Node Arguments:              ");
      for (int j = 0 ; j < tcc.getNodeArguments().length ; j++) {
	System.out.print(tcc.getNodeArguments()[j] + " ");
      }
      System.out.println();
      try {
	Thread.sleep(1000 * tcc.getHowLongBeforeStart());
	threadList.add(runRemoteNode(tcc));
      }
      catch (Exception e) {
	e.printStackTrace();
	Assert.fail("Unable to execute remote node: " + e);
      }
    }
    try {
      for (int i = 0 ; i < threadList.size() ; i++) {
	System.out.println("Waiting for thread to die");
	((Thread)threadList.get(i)).join();
      }
    }
    catch (java.lang.InterruptedException e) {
      Assert.fail("Unable to execute remote node");
    }

    // Run Post operation
    try {
      experiment.getPostOperation().invokeMethod(null);
    }
    catch (Exception e) {
      Assert.fail("Unable to execute pre-operation:" + e);
    }

  }
  
  private Thread runRemoteNode(NodeConfiguration tcc) {
    RemoteNode rn = new RemoteNode(tcc, testResult, this);
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

    public void run() {
      try {
	Runtime thisApp = Runtime.getRuntime();
	Process nodeApp = null;

	String jarFile1 = userDir + File.separator + classPath + File.separator + "junitTests.jar";
	String jarFile2 = System.getProperty("org.cougaar.install.path") + File.separator
	  + "sys" + File.separator + "junit.jar";

	String commandLine = "/usr/bin/ssh " + tcc.getHostName()
	  + " " + System.getProperty("java.home") + File.separator + "bin" + File.separator
	  + "java -classpath " + jarFile1 + ":" + jarFile2
	  + " -Djava.rmi.server.codebase=file://" + jarFile1 + ":file://" + jarFile2
	  + " -Djava.security.policy="
	  + userDir + File.separator + junitConfigPath + File.separator + "JavaPolicy.conf"
	  + " -Dorg.cougaar.install.path=" + System.getProperty("org.cougaar.install.path")
	  + " -Dorg.cougaar.workspace=" + System.getProperty("org.cougaar.workspace")
	  + " -Dorg.cougaar.securityservices.configs="
	  + userDir + File.separator + System.getProperty("org.cougaar.securityservices.configs")
	  + " -Dorg.cougaar.securityservices.base="
	  + userDir + File.separator +System.getProperty("org.cougaar.securityservices.base")
	  + " -Dorg.cougaar.securityservices.classes="
	  + userDir + File.separator +System.getProperty("org.cougaar.securityservices.classes")
	  + " -Dorg.cougaar.securityservices.regress="
	  + userDir + File.separator +System.getProperty("org.cougaar.securityservices.regress")
	  + " -Dorg.cougaar.junit.config.path="
	  + userDir + File.separator +System.getProperty("org.cougaar.junit.config.path")
	  + " test.org.cougaar.core.security.simul.NodeServer "
	  + tcc.getRmiRegistryPort() + "";

	//System.out.println("Executing " + commandLine);
	nodeApp = thisApp.exec(commandLine);

	ProcessGobbler pg = new ProcessGobbler(resultPath, "ssh-" + tcc.getHostName(), nodeApp);
	pg.dumpProcessStream();

	ProcessMonitor pm = new ProcessMonitor(nodeApp, testResult, test);
	pm.start();
	// Give the remote application some time to start...
	Thread.sleep(4000);

	Registry registry = LocateRegistry.getRegistry(tcc.getHostName(), tcc.getRmiRegistryPort());
	String list[] = registry.list();
	System.out.println("Registered objects in " + tcc.getHostName() + " registry: ");
	for (int i = 0 ; i < list.length ; i++) {
	  System.out.println(list[i]);
	}
	RemoteControl nodeServer = (RemoteControl)registry.lookup("NodeServer");

	Assert.assertNotNull("Could not create Remote NodeServer", nodeServer);

	System.out.println("Calling startNode on remote server");
	nodeServer.startNode(tcc);
      } catch (Exception e) { 
	e.printStackTrace();
	testResult.addFailure(test, new AssertionFailedError("Unable to start node: " + e));
      } catch (AssertionFailedError e) {
	testResult.addFailure(test, e);
      }
    }
  }

  private class ProcessMonitor
    extends Thread
  {
    private Process nodeApp;
    private TestResult testResult;
    private Test test;

    public ProcessMonitor(Process nodeApp, TestResult testResult, Test test) {
      if (testResult == null) {
	throw new IllegalArgumentException("testResult is null");
      }
      if (test == null) {
	throw new IllegalArgumentException("test is null");
      }
      this.nodeApp = nodeApp;
      this.testResult = testResult;
      this.test = test;
    }

    public void run() {
      try {
	nodeApp.waitFor();
	if (nodeApp.exitValue() != 0) {
	  Assert.fail("Unable to establish SSH session");
	}
      } catch (Exception e) { 
	e.printStackTrace();
	testResult.addFailure(test, new AssertionFailedError("Unable to start node: " + e));
      } catch (AssertionFailedError e) {
	testResult.addFailure(test, e);
      }
    }
  }

  private class ThreadedProtectable
    implements Protectable
  {
    private TestCase testCase;
    public ThreadedProtectable(TestCase tc) {
      testCase = tc;
    }
    public void protect() throws Throwable {
      testCase.runBare();
    }
  }
}
