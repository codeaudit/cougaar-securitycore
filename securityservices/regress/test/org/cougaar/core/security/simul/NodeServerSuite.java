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
import java.net.*;
import java.util.regex.*;
import junit.framework.*;
import java.rmi.Naming;
import java.rmi.registry.*;

public class NodeServerSuite
  extends TestCase
{
  /** A list of NodeConfiguration */
  private Vector nodeConfList;
  private String userName;
  /** The top-level directory of the experiment. */
  private String resultPath;

  private SerializableTestResult experimentTestResult;
  private TestResult testResult;
  private ConfigParser configParser;
  private ExperimentMapper experimentMapper;
  private String configFileName;

  private Experiment experiment;

  /** A list of all the hosts used in this experiment. */
  private Hashtable hostList;

  public NodeServerSuite(String name) {
    super(name);
  }

  public void setUp() {
    System.out.println("Test setup...");

    resultPath = System.getProperty("junit.test.result.path");
    Assert.assertNotNull("Unable to get test output path. Set junit.test.result.path",
			 resultPath);
    System.out.println("Result path: " + resultPath);
    resultPath = getCanonicalPath(resultPath);
    System.out.println("Result path: " + resultPath);

    userName = System.getProperty("user.name");
    Assert.assertNotNull("Unable to get user name", userName);

    configFileName = System.getProperty("junit.config.file");
    Assert.assertNotNull("Unable to get junit.config.file", configFileName);

    try {
      experimentMapper = new ExperimentMapper();
      System.out.println("Parsing " + configFileName);
      experiment = (Experiment) experimentMapper.fromXML(configFileName);

      // Set link to result file
      File f = new File(resultPath);
      String link = "<a href=\"./results/" + f.getName() + "/TEST-results.xml\">TEST-results.xml</a>";
      experiment.setJunitResultLink(link);

      experiment.setTestResult(experimentTestResult);
      startRmiServers();
      // Save experiment to file
      saveExperiment(experiment);
    }
    catch (Exception e) {
      e.printStackTrace();
      Assert.fail("Error during Test suite setUp: " + e);
    }
  }

  public void tearDown() {
    System.out.println("Test tear down...");

    experimentTestResult = new SerializableTestResult(testResult.failures(),
						      testResult.errors(),
						      testResult.runCount());
    // Analyze results
    for (int i = 0 ; i < nodeConfList.size() ; i++) {
      NodeConfiguration tcc = (NodeConfiguration) nodeConfList.get(i);
      analyzeResult(tcc);
    }
    saveExperiment(experiment);
    System.out.println(experiment.toString());
  }

  /**
   * Creates a default TestResult object
   *
   * @see TestResult
   */
  protected TestResult createResult() {
    System.out.println("Creating new SerializableTestResult");
    return new SerializableTestResult();
  }

  /**
   * A convenience method to run this test, collecting the results with a
   * default TestResult object.
   *
   * @see TestResult
  public TestResult run() {
    System.out.println("Starting test...");
    SerializableTestResult result= (SerializableTestResult)createResult();

    run(result);
    System.out.println("End test...");
    return result;
  }
   */

  /**
   * Runs the test case and collects the results in TestResult.
   */
  public void run(TestResult result) {
    System.out.println("Starting test...");
    this.experimentTestResult = new SerializableTestResult();
    this.testResult = result;

    result.startTest(this);
    Protectable p = new ThreadedProtectable(this);
    result.runProtected(this, p);
    result.endTest(this);

    System.out.println("End test...");
  }

  public void testExperiment() {
    ArrayList threadList = new ArrayList();
    experimentSetup();

    for (int i = 0 ; i < nodeConfList.size() ; i++) {
      NodeConfiguration tcc = (NodeConfiguration) nodeConfList.get(i);

      System.out.println("#####################################################");
      System.out.println("Test Case # " + i);
      System.out.print("Node Arguments:              ");
      for (int j = 0 ; j < tcc.getNodeArguments().length ; j++) {
	System.out.print(tcc.getNodeArguments()[j] + " ");
      }
      System.out.println();

      // Create new test case
      NodeServerTest nst = new NodeServerTest("testRunNode");
      nst.setNodeConfiguration(tcc);
      nst.setThreadList(threadList);

      // Save test results
      SerializableTestResult nodeTestResult = new SerializableTestResult();
      tcc.setTestResult(nodeTestResult);

      // Run test case
      //nodeTestResult.startTest(nst);
      //Protectable p = new ThreadedProtectable(nst);
      //nodeTestResult.runProtected(nst, p);
      //nodeTestResult.endTest(nst);

      try {
	nst.run(nodeTestResult);
      }
      catch (Throwable t) {
	// Catch errors here otherwise assertion failures will be added to the experiment
	System.out.println("Caught exception while running node: " + tcc.getNodeName());
      }
    }
    experimentTearDown(threadList);
  }

  public static String getCanonicalPath(String fileName) {
    String can = null;
    File f = new File(fileName);
    try {
      can = f.getCanonicalPath();
    }
    catch (IOException e) {
      Assert.fail("Unable to get canonical path for " + fileName);
    }
    return can;
  }

  private void analyzeResult(NodeConfiguration tcc) {
    Date curDate = new Date();
    TestResult tr = tcc.getTestResult();
    tcc.setAnalyzisDate(curDate);
    if (tr != null) {
      tcc.setErrors(tr.errorCount());
      tcc.setFailures(tr.failureCount());
      tcc.setLogFilesUrls();
    }
    //tcc.setCompletionTime();
    //tcc.setStartTime();
    //tcc.setLogFilesUrls();
    //tcc.setResultFilesUrls();
  }

  private void experimentSetup() {
    nodeConfList = experiment.getNodeConfiguration();
    System.out.println(experiment.toString());

    // Run Pre operation
    try {
      experiment.getPreOperation().invokeMethod(null);
    }
    catch (Exception e) {
      Assert.fail("Unable to execute pre-operation:" + e);
    }
  }

  private void experimentTearDown(ArrayList threadList) {
    System.out.println("ExperimentTearDown: Waiting for all nodes to die");
    try {
      if (nodeConfList.size() != threadList.size()) {
	Assert.fail("Inconsistent number of nodes. " + nodeConfList.size()
		    + " nodes expected. Found " + threadList.size() + " processes");
      }
      for (int i = 0 ; i < threadList.size() ; i++) {
	NodeConfiguration tcc = (NodeConfiguration) nodeConfList.get(i);
	System.out.println("Waiting for node " + tcc.getNodeName() + " to die");
	((Thread)threadList.get(i)).join();
      }
    }
    catch (Exception e) {
      Assert.fail("Unable to execute remote node");
    }

    // Run Post operation
    try {
      experiment.getPostOperation().invokeMethod(null);
    }
    catch (Exception e) {
      Assert.fail("Unable to execute pre-operation:" + e);
    }

    killRmiServers();
  }

  private void saveExperiment(Experiment exp) {
    try {
      FileOutputStream fo = new FileOutputStream(resultPath + File.separator + "experiment.dat");
      ObjectOutputStream os = new ObjectOutputStream(fo);
      os.writeObject(exp);
      os.close();
    }
    catch (Exception e) {
      System.out.println("Unable to save experiment:" + e);
      e.printStackTrace();
    }
  }

  private void saveExperimentInfo(NodeConfiguration tcc) {
    try {
      FileOutputStream fo = new FileOutputStream(resultPath + File.separator + "summary.xml");
      PrintWriter pw = new PrintWriter(fo);

      Date currentDate = new Date();
      SimpleDateFormat df = new SimpleDateFormat("yyyy.MM.dd-HH:mm:ss");
      String starttime = df.format(currentDate);

      pw.println("<experiment name="
		 + "\"" + System.getProperty("junit.test.desc") + "\""
		 + " starttime="
		 + "\"" + starttime + "\">");
      pw.println("</experiment>");
      pw.close();
    }
    catch (Exception e) {
      System.out.println("Unable to save summary:" + e);
      e.printStackTrace();
    }
  }


  private void startRmiServers() {
    // Start the RMI servers on every machine in the experiment.
    hostList = new Hashtable();
    for (int i = 0 ; i < experiment.getNodeConfiguration().size() ; i++) {
      NodeConfiguration tcc = (NodeConfiguration) experiment.getNodeConfiguration().get(i);
      String hostname = tcc.getHostName();
      Object o = hostList.get(hostname);
      if (o == null) {
	// RMI server is not started yet. Start it.
	RmiServerInfo ri = new RmiServerInfo();
	ri.hostName = tcc.getHostName();
	ri.rmiPort = tcc.getRmiRegistryPort();

	startRemoteControl(tcc, ri);
	hostList.put(hostname, ri);
      }
    }
    try {
      // Give the remote RMI servers some time to start...
      Thread.sleep(5000);
    }
    catch (Exception e) {}

    // Then try to get the remote controls
    Enumeration keys = hostList.keys();
    while (keys.hasMoreElements()) {
      String hostName = (String) keys.nextElement();
      RmiServerInfo rsi = (RmiServerInfo) hostList.get(hostName);

      rsi.remoteControl = null;
      try {
	rsi.remoteControl = getRemoteControl(hostName, rsi.rmiPort);
      }
      catch (Exception e) {
	System.out.println("Unable to get remote RMI server on " + hostName + " - Reason: " + e);
      }
      if (rsi.remoteControl == null) {
	Assert.fail("Could not create RMI server on " + hostName);
      }
    }
  }

  private RemoteControl getRemoteControl(String hostName, int rmiPort)
    throws java.rmi.RemoteException, java.rmi.NotBoundException {
    RemoteControl nodeServer = null;

    Registry registry = LocateRegistry.getRegistry(hostName, rmiPort);
    String list[] = registry.list();
    System.out.println("Registered objects in " + hostName + " registry: ");
    for (int i = 0 ; i < list.length ; i++) {
      System.out.println(list[i]);
    }
    nodeServer = (RemoteControl)registry.lookup("NodeServer");
    return nodeServer;
  }

  private void startRemoteControl(NodeConfiguration tcc, RmiServerInfo rsi) {
    String classPath;
    String junitConfigPath;
    String userDir;

    Runtime thisApp = Runtime.getRuntime();
    Process nodeApp = null;

    // First, try to figure out if an older version of the RMI server is running.
    // If so, kill it and restart it.

    RemoteControl nodeServer = null;
    try {
      nodeServer =
	(RemoteControl) getRemoteControl(tcc.getHostName(), tcc.getRmiRegistryPort());
    }
    catch (Exception e) {
      System.out.println("No server running on " + tcc.getHostName() + ". Will start it");
    }

    if (nodeServer != null) {
      // Kill the RMI server
      System.out.println("Killing old remote RMI server on " + tcc.getHostName());
      try {
	if (nodeServer != null) {
	  nodeServer.killServer();
	}
	// Give some time for the process to die
	Thread.sleep(2000);
      }
      catch (Exception e) {
	System.out.println("Unable to kill old RMI server on " + tcc.getHostName() + ": " + e);
	e.printStackTrace();
      }
    }

    // In addition, kill all java processes, but only on remote machines otherwise we will kill ourselves.

    try {
      InetAddress myHost = InetAddress.getLocalHost();
      InetAddress otherHost = InetAddress.getByName(tcc.getHostName());
      if (!myHost.equals(otherHost)) {
	// Kill java process
	System.out.println("Killing java processes on " + tcc.getHostName());
	String commandLine = "/usr/bin/ssh " + tcc.getHostName() + " killall -w java";
	Process killJava = thisApp.exec(commandLine);
	killJava.waitFor();
      }
    }
    catch (Exception e) {
      Assert.fail("Unable to kill java processes on " + tcc.getHostName() + ": " + e);
    }

    classPath = System.getProperty("org.cougaar.securityservices.classes");
    Assert.assertNotNull("Unable to get org.cougaar.securityservices.classes", classPath);
    classPath = NodeServerSuite.getCanonicalPath(classPath);

    junitConfigPath = System.getProperty("org.cougaar.junit.config.path");
    Assert.assertNotNull("Unable to get org.cougaar.junit.config.path", junitConfigPath);
    junitConfigPath = NodeServerSuite.getCanonicalPath(junitConfigPath);

    userDir = System.getProperty("user.dir");
    Assert.assertNotNull("Unable to get user dir", userDir);

    String jarFile1 = getCanonicalPath(classPath + File.separator + "junitTests.jar");

    String jarFile2 = getCanonicalPath(System.getProperty("org.cougaar.install.path")
						       + File.separator
						       + "sys" + File.separator + "junit.jar");
    String jarFile3 = getCanonicalPath(System.getProperty("org.cougaar.install.path")
						       + File.separator
						       + "sys" + File.separator + "httpunit.jar");
    String jarFile4 = getCanonicalPath(System.getProperty("org.cougaar.install.path")
						       + File.separator
						       + "sys" + File.separator + "Tidy.jar");
    String commandLine = "/usr/bin/ssh " + tcc.getHostName()
      + " " + System.getProperty("java.home") + File.separator + "bin" + File.separator
      + "java -classpath " + jarFile1 + ":" + jarFile2 + ":" + jarFile3 + ":" + jarFile4;

    Properties props = (Properties)System.getProperties().clone();
    // Override some properties
    props.put("java.rmi.server.codebase", "file://" + jarFile1 + ":file://" + jarFile2);
    props.put("java.security.policy",
	      getCanonicalPath(junitConfigPath + File.separator + "JavaPolicy.conf"));
    props.put("org.cougaar.junit.config.path",
	      getCanonicalPath(System.getProperty("org.cougaar.junit.config.path")));
    props.put("junit.test.result.path",
	      getCanonicalPath(System.getProperty("junit.test.result.path")));
    props.put("org.cougaar.securityservices.configs",
	      getCanonicalPath(System.getProperty("org.cougaar.securityservices.configs")));
    props.put("org.cougaar.securityservices.base",
	      getCanonicalPath(System.getProperty("org.cougaar.securityservices.base")));
    props.put("org.cougaar.securityservices.classes",
	      getCanonicalPath(System.getProperty("org.cougaar.securityservices.classes")));
    props.put("org.cougaar.securityservices.regress",
	      getCanonicalPath(System.getProperty("org.cougaar.securityservices.regress")));

    Enumeration enum = props.propertyNames();
    while (enum.hasMoreElements()) {
      String key = (String) enum.nextElement();
      if (
	(key.startsWith("java.") && !(key.startsWith("java.security.") || key.startsWith("java.rmi.")))
	|| key.startsWith("sun.")
	|| key.startsWith("line.")
	|| key.startsWith("file.")
	|| key.startsWith("user.")
	|| key.startsWith("os.")
	|| key.startsWith("path.")) {
	continue;
      }
      String val = props.getProperty(key);
      commandLine = commandLine + " -D" + key + "=" + val;
    }

    //
    commandLine = commandLine
      + " test.org.cougaar.core.security.simul.NodeServer "
      + tcc.getRmiRegistryPort() + "";

    tcc.setResultPath(getCanonicalPath(System.getProperty("junit.test.result.path")));
    String logfile = getCanonicalPath(System.getProperty("org.cougaar.workspace") + File.separator +
				      "log4jlogs" + File.separator + tcc.getExperimentName() + File.separator
				      + tcc.getNodeName() +  File.separator + "log4j.html");
    File logf = new File(logfile);
    File parent = logf.getParentFile();
    parent.mkdirs();
    tcc.setLog4jLogFile(logfile);

    try {
      System.out.println("Executing RMI server on " + rsi.hostName);
      System.out.println(commandLine + '\n');
      nodeApp = thisApp.exec(commandLine);
      rsi.rmiServerProcess = nodeApp;

      ProcessGobbler pg = new ProcessGobbler(resultPath,
					     "ssh-" + tcc.getHostName(), nodeApp);
      pg.dumpProcessStream();
      experiment.addRmiServerLogFile(pg.getErrFile());
      experiment.addRmiServerLogFile(pg.getOutFile());

      ProcessMonitor pm = new ProcessMonitor(nodeApp, experimentTestResult, this);
      pm.start();

    } catch (Exception e) { 
      e.printStackTrace();
      Assert.fail("Unable to start RMI server on " + tcc.getHostName());
    }
  }

  private void killRmiServers() {
    // Kill all the RMI servers
    Enumeration keys = hostList.keys();
    while (keys.hasMoreElements()) {
      String hostName = (String) keys.nextElement();
      RmiServerInfo rsi = (RmiServerInfo) hostList.get(hostName);
      RemoteControl nodeServer = rsi.remoteControl;
      Process nodeApp = rsi.rmiServerProcess;

      try {
	System.out.println("Killing remote RMI server on " + rsi.hostName);
	if (nodeServer != null) {
	  nodeServer.killServer();
	}
      }
      catch (Exception e) {
	e.printStackTrace();
	Assert.fail("Unable to call killServer() on RMI server, host=" + rsi.hostName + ": " + e);
      }

      try {
	System.out.println("Waiting for SSH process to die on " + rsi.hostName);
	if (nodeApp != null) {
	  nodeApp.destroy();
	}
      }
      catch (Exception e) {
	e.printStackTrace();
	Assert.fail("Unable to terminate RMI server on " + rsi.hostName + ": " + e);
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
	  testResult.addFailure(test, new AssertionFailedError("RMI process return value not null"));
	}
      } catch (InterruptedException e) { 
	e.printStackTrace();
	testResult.addFailure(test, new AssertionFailedError("This thread has been interrupted unexpectedly:" + e));
      } catch (AssertionFailedError e) {
	testResult.addFailure(test, e);
      }
    }
  }

}
