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

public class NodeServerTest
  extends TestCase
{
  private NodeServer ns;

  /** A list of TestCaseConf */
  private ArrayList testCaseConfList;
  private String junitConfigPath;
  private String userDir;

  public NodeServerTest(String name) {
    super(name);
  }

  public void setUp() {
    ns = new NodeServer();
    Assert.assertNotNull("Could not create NodeServer", ns);

    junitConfigPath = System.getProperty("org.cougaar.junit.config.path");
    Assert.assertNotNull("Unable to get org.cougaar.junit.config.path", junitConfigPath);

    userDir = System.getProperty("user.dir");
    Assert.assertNotNull("Unable to get user dir", userDir);
    System.out.println("Startup directory is " + userDir);

  }

  public void testNodes() {
    readConfigurationFile();
    for (int i = 0 ; i < testCaseConfList.size() ; i++) {
      TestCaseConf tcc = (TestCaseConf) testCaseConfList.get(i);
      System.out.println("#####################################################");
      System.out.println("Test Case # " + i);
      System.out.println("Node Startup Directory: " + tcc.getDirectoryName());
      System.out.println("Property File:          " + tcc.getPropertyFile());
      System.out.println("Max Execution Time:     " + tcc.getMaxExecutionTime());
      System.out.print("Arguments:              ");
      for (int j = 0 ; j < tcc.getArguments().length ; j++) {
	System.out.print(tcc.getArguments()[j] + " ");
      }
      System.out.println();
      ns.startNode(tcc.getArguments(), tcc.getDirectoryName(),
		   tcc.getPropertyFile(), tcc.getMaxExecutionTime());
    }
  }

  private void readConfigurationFile() {
    // 1) Directory where the node should be started
    // 2) Linux.props file
    // 3) Command-Line arguments

    testCaseConfList = new ArrayList();

    try {
      File f = null;
      String fileName = junitConfigPath + File.separator + "NodeServerTestCase.conf";
      f = new File(fileName);
      if (!f.exists()) {
	Assert.assertTrue("Unable to find " + fileName, false);
	return;
      }
      FileReader filereader=new FileReader(f);
      BufferedReader buffreader=new BufferedReader(filereader);
      String linedata=new String();

      while((linedata=buffreader.readLine())!=null) {
	linedata.trim();
	if(linedata.startsWith("#")) {
	  continue;
	}
	StringTokenizer st = new StringTokenizer(linedata);
	if (!st.hasMoreTokens()) {
	  // Empty line. Continue
	  continue;
	}

	int maxTime = Integer.valueOf(st.nextToken()).intValue();

	if (!st.hasMoreTokens()) {
	  Assert.assertTrue("Incorrect configuration file. Expected Directory Name", false);
	  throw new RuntimeException("Incorrect configuration file. Expected Directory Name");
	}
	String directoryName = parseString(st.nextToken());

	if (!st.hasMoreTokens()) {
	  Assert.assertTrue("Incorrect configuration file. Expected property File", false);
	  throw new RuntimeException("Incorrect configuration file. Expected property File");
	}
	String propFile = parseString(st.nextToken());
	ArrayList argsList = new ArrayList();
	while (st.hasMoreTokens()) {
	  argsList.add(parseString(st.nextToken()));
	}
	String[] args = (String[]) argsList.toArray(new String[1]);
	TestCaseConf tcc = new TestCaseConf(directoryName,
					    propFile,
					    args, maxTime);
	testCaseConfList.add(tcc);
      }
    }
    catch(FileNotFoundException fnotfoundexp) {
      Assert.assertTrue("User parameter configuration file not found", false);
    }
    catch(IOException ioexp) {
      Assert.assertTrue("Cannot read User parameter configuration file: " + ioexp, false);
    }
  }

  private String parseString(String s) {
    Pattern p_javaprop = Pattern.compile("\\$\\{.*\\}");
    Matcher matcher = null;
    StringBuffer sb = new StringBuffer();
    boolean result = false;

    /* Search for java properties patterns.
     * ${java_property} will be replaced by the value of the java property.
     * For example:
     *   ${org.cougaar.node.name} will be replaced by the value
     *   of the org.cougaar.node.name java property.
     */
    matcher = p_javaprop.matcher(s);
    result = matcher.find();
    // Loop through and create a new String 
    // with the replacements
    while(result) {
      String token = matcher.group();
      String propertyName = token.substring(2, token.length() - 1);
      String propertyValue = System.getProperty(propertyName);
      if (propertyValue == null) {
	Assert.assertTrue("The " + propertyName + " property is not defined", false);
	throw new RuntimeException("The " + propertyName + " property is not defined");
      }
      matcher.appendReplacement(sb, propertyValue);
      result = matcher.find();
    }
    // Add the last segment of input to 
    // the new String
    matcher.appendTail(sb);
    s = sb.toString();

    return s;
  }

  private class TestCaseConf {
    private String directoryName;
    private String propertyFile;
    private String arguments[];
    private int maxExecutionTime;

    public TestCaseConf(String dn, String propFile, String args[], int maxTime) {
      directoryName = dn;
      propertyFile = propFile;
      arguments = args;
      maxExecutionTime = maxTime;
    }

    public String getDirectoryName() {
      return directoryName;
    }
    public String getPropertyFile() {
      return propertyFile;
    }
    public String[] getArguments() {
      return arguments;
    }
    public int getMaxExecutionTime() {
      return maxExecutionTime;
    }
  }
}
