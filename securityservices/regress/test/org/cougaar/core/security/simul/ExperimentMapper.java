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
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import junit.framework.*;

import org.w3c.dom.*;

public class ExperimentMapper
  extends SaxMapper
{
  private Experiment target;
  private Stack stack = new MyStack();

  private Hashtable attributeTable;
  private boolean replaceJavaProperties = true;
  private boolean replaceAttributes = true;

  private String junitConfigPath;
  private String userName;

  private Properties props;

  public ExperimentMapper() {
    junitConfigPath = System.getProperty("org.cougaar.junit.config.path");
    Assert.assertNotNull("Unable to get org.cougaar.junit.config.path", junitConfigPath);

    userName = System.getProperty("user.name");
    Assert.assertNotNull("Unable to get user name", userName);
    
    replaceJavaProperties(true);

    PropertyFile pf = new PropertyFile();
    props = pf.readCustomPropertiesFile();
  }

  public Object getMappedObject() {
    return target;
  }

  public static String NODE_TEST = "nodeTest";
  public static String HOW_LONG = "howLongBeforeStart";
  public static String MAX_EXEC_TIME = "maxExecTime";
  public static String HOST_NAME = "hostName";
  public static String NODE_STARTUP_DIRECTORY = "nodeStartupDirectory";
  public static String PROPERTY_FILE = "propertyFile";
  public static String NODE_ARGUMENTS = "nodeArguments";
  public static String NODE_DESCRIPTION = "nodeDescription";

  private String getCanonicalPath(String fileName) {
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

  public TagTracker createTagTrackerNetwork() {
    SaxMapperLog.trace("Creating tag track network");

    // -- create root: /
    TagTracker root = new TagTracker() {
	public void onDeactivate() {
	  // The root will be deactivated when
	  // parsing a new document begins.

	  // clear the stack
	  stack.removeAllElements();

	  // create the root "dir" object.
	  target = new Experiment();

	  // push the root dir on the stack...
	  stack.push( target );
	}
      };

    // -- create root: /
    TagTracker experiment = new TagTracker() {
	public void onStart( String namespaceURI,
			     String localName,
			     String qName,
			     Attributes attr ) {
	  String desc = parseContents(attr.getValue("description"));
	  SaxMapperLog.trace("Setting experiment description");
	  target.setExperimentDescription(desc);
	  target.setExperimentName(System.getProperty("junit.test.desc"));
	}
      };
    // Set tracking relationships...
    root.track("experiment", experiment);

    // -- create action nodeTest
    TagTracker nodeConf = new TagTracker() {
	private NodeConfiguration currentNodeConf;

	public void onStart( String namespaceURI,
			     String localName,
			     String qName,
			     Attributes attr ) {
	  // Capture the node name...
	  String nodeName = parseContents(attr.getValue("name"));
	  currentNodeConf = new NodeConfiguration();
	  currentNodeConf.setNodeName(nodeName);

	  // Set top-level directory
	  File f1 = new File(System.getProperty("org.cougaar.securityservices.base"));
	  try {
	    String top = f1.getCanonicalPath();
	    currentNodeConf.setTopLevelDirectory(top);
	  }
	  catch (IOException e) {
	    System.err.println("Unable to get top level directory");
	  }
	  
	  // Set user parameters
	  setUserParameters(currentNodeConf);

	  Experiment temp = (Experiment) stack.peek();

	  // Log a trace message...
	  SaxMapperLog.trace( "Creating node configuration: " + nodeName );

	  // Connect new node configuration to its parent...
	  temp.addNodeConfiguration( currentNodeConf );

	  // Make the new node configuration the active element...
	  stack.push(currentNodeConf);
	}

	public void onEnd(   String namespaceURI,
			     String localName,
			     String qName,
			     CharArrayWriter contents ){
	  // Clean up the directory stack...
	  stack.pop();
	}
      };

    // Set tracking relationships...
    root.track( "experiment/nodeTest", nodeConf);

    // -- create action /listing/directory  and */directory
    TagTracker nodeConfItem = new TagTracker() {
	private NodeConfiguration currentNodeConf;

	public void onStart( String namespaceURI,
			     String localName,
			     String qName,
			     Attributes attr ) {
	  currentNodeConf = (NodeConfiguration) stack.pop();
	  Experiment temp = (Experiment) stack.peek();
          stack.push(currentNodeConf);

          currentNodeConf.setExperimentName(temp.getExperimentName());
	  // Log a trace message...
	  SaxMapperLog.trace( "Creating node configuration item: " + localName );
	}

	public void onEnd(   String namespaceURI,
			     String localName,
			     String qName,
			     CharArrayWriter contents ){
	  String value = getContents();

	  // Log a trace message...
	  SaxMapperLog.trace( "Node configuration item: " + localName + ": " + value);

	  if (localName.equals(HOW_LONG)) {
	    int howLong = Integer.valueOf(value).intValue();
	    currentNodeConf.setHowLongBeforeStart(howLong);
	  }
	  else if (localName.equals(MAX_EXEC_TIME)) {
	    int maxTime = Integer.valueOf(value).intValue();
	    currentNodeConf.setMaxExecutionTime(maxTime);
	  }
	  else if (localName.equals(HOST_NAME)) {
	    currentNodeConf.setHostName(value);
	  }
	  else if (localName.equals(NODE_DESCRIPTION)) {
	    currentNodeConf.setNodeDescription(value);
	  }
	  else if (localName.equals(NODE_STARTUP_DIRECTORY)) {
	    currentNodeConf.setNodeStartupDirectoryName(getCanonicalPath(currentNodeConf.getTopLevelDirectory()
							+ File.separator + value));
	  }
	  else if (localName.equals(PROPERTY_FILE)) {
	    currentNodeConf.setPropertyFile(value);
	  }
	  else if (localName.equals(NODE_ARGUMENTS)) {
	    ArrayList argsList = new ArrayList();
	    StringTokenizer st = new StringTokenizer(value);
	    while (st.hasMoreTokens()) {
	      argsList.add(st.nextToken());
	    }
	    String[] args = (String[]) argsList.toArray(new String[1]);
	    currentNodeConf.setNodeArguments(args);
	  }
	}
      };

    nodeConf.track( "howLongBeforeStart", nodeConfItem);
    nodeConf.track( "maxExecTime", nodeConfItem);
    nodeConf.track( "hostName", nodeConfItem);
    nodeConf.track( "nodeDescription", nodeConfItem);
    nodeConf.track( "nodeStartupDirectory", nodeConfItem);
    nodeConf.track( "propertyFile", nodeConfItem);
    nodeConf.track( "nodeArguments", nodeConfItem);

    TagTracker nodeConfProperty = new TagTracker() {
	private NodeConfiguration currentNodeConf;
	public void onStart( String namespaceURI,
			     String localName,
			     String qName,
			     Attributes attr ) {
	  currentNodeConf = (NodeConfiguration) stack.peek();
	  String key = parseContents(attr.getValue("name"));
	  String value = parseContents(attr.getValue("value"));
	  currentNodeConf.addAdditionalVmProperties(key, value);
	}
      };
    nodeConf.track("property", nodeConfProperty);

    // -- create action experiment/operation
    //    and nodeTest/operation
    TagTracker operation = new TagTracker() {
	private OperationConf currentOp;

	public void onStart( String namespaceURI,
			     String localName,
			     String qName,
			     Attributes attr ) {
	  String opType = parseContents(attr.getValue("type"));
	  currentOp = new OperationConf(opType);

	  // The parent can be an Experiment or a NodeConfiguration
	  Object o = stack.peek();
	  if (o instanceof Experiment) {
	    switch (currentOp.getType()) {
	    case OperationConf.BEFORE:
	      ((Experiment)o).setPreOperation(currentOp);
	      break;
	    case OperationConf.AFTER:
	      ((Experiment)o).setPostOperation(currentOp);
	      break;
	    }
	  }
	  else {
	    switch (currentOp.getType()) {
	    case OperationConf.BEFORE:
	      ((NodeConfiguration)o).setPreOperation(currentOp);
	      break;
	    case OperationConf.AFTER:
	      ((NodeConfiguration)o).setPostOperation(currentOp);
	      break;
	    }
	  }

	  // push
	  stack.push(currentOp);
	}

	public void onEnd(   String namespaceURI,
			     String localName,
			     String qName,
			     CharArrayWriter contents ){
	  String value = getContents();
	  if (localName.equals("class")) {
	    currentOp.setClassName(value);
	  }
	  else if (localName.equals("method")) {
	    currentOp.setMethodName(value);
	  }
	  stack.pop();
	}

      };

    root.track("experiment/operation", operation);
    nodeConf.track( "operation", operation);

    // -- create action experiment/operation
    //    and nodeTest/operation
    TagTracker operationItem = new TagTracker() {
	private OperationConf currentOp;
	public void onStart( String namespaceURI,
			     String localName,
			     String qName,
			     Attributes attr ) {
	  currentOp = (OperationConf) stack.peek();
	}

	public void onEnd(   String namespaceURI,
			     String localName,
			     String qName,
			     CharArrayWriter contents ){
	  String value = getContents();
	  if (localName.equals("class")) {
	    currentOp.setClassName(value);
	  }
	  else if (localName.equals("method")) {
	    currentOp.setMethodName(value);
	  }
	  else if (localName.equals("argument")) {
	    currentOp.setArgument(value);
	  }
	}
      };
    operation.track("class", operationItem);
    operation.track("method", operationItem);
    operation.track("argument", operationItem);

    return root;
  }

  public void replaceAttributes(boolean value) {
    replaceAttributes = value;
  }
  public void replaceJavaProperties(boolean value) {
    replaceJavaProperties = value;
  }

  public void setAttributeTable(Hashtable hash) {
    attributeTable = hash;
  }

  protected String parseContents(String s) {
    Pattern p_javaprop = Pattern.compile("\\$\\{[a-zA-Z\\.]*\\}");
    Pattern p_keyvalue = Pattern.compile("\\$\\[[a-zA-Z\\.]*\\]");
    Matcher matcher = null;
    StringBuffer sb = new StringBuffer();
    boolean result = false;

    //System.out.println("Parsing " + s);
    if (s == null) {
      return s;
    }
    try {
      if (replaceJavaProperties) {
	//if (log.isDebugEnabled()) {
	//log.debug("Looking up java property pattern in " + s);
	//}
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
	  String propertyValue = props.getProperty(propertyName);
	  if (propertyValue == null) {
	    propertyValue = "";
	    Assert.fail("Property " + propertyName + " should be set");
	  }
	  matcher.appendReplacement(sb, propertyValue);
	  result = matcher.find();
	}
	// Add the last segment of input to 
	// the new String
	matcher.appendTail(sb);
	s = sb.toString();
      }

      if (attributeTable != null && replaceAttributes) {
	/* Replace attributes with their value.
	 * $[attribute] will be replaced by the value of the attribute.
	 * For example:
	 *   ${attr1} will be replaced by the value
	 *   of the attr1 attribute.
	 */
	sb.setLength(0);
	matcher = p_keyvalue.matcher(s);
	result = matcher.find();
	// Loop through and create a new String 
	// with the replacements
	while(result) {
	  String token = matcher.group();
	  String attributeName = token.substring(2, token.length() - 1);
	  String attributeValue = (String) attributeTable.get(attributeName);
	  matcher.appendReplacement(sb, attributeValue);
	  result = matcher.find();
	}
	// Add the last segment of input to 
	// the new String
	matcher.appendTail(sb);
	s = sb.toString();
      }
    }
    catch (Exception e) {
      e.printStackTrace();
      System.out.println("Error parsing string " + s + " - " + e);
    }
    //System.out.println("Parsed String: " + s);
    
    return s;
  }
  private void setUserParameters(NodeConfiguration tcc) {
    File userParamFile = new File(getCanonicalPath(junitConfigPath
						   + File.separator + "userParameters.conf"));
    if (!userParamFile.exists()) {
      throw new RuntimeException("Unable to find user parameter configuration file");
    }
    try {
      FileReader filereader=new FileReader(userParamFile);
      BufferedReader buffreader=new BufferedReader(filereader);
      String linedata=new String();

      // Set default values
      tcc.setHttpPort(8800);
      tcc.setHttpsPort(9800);
      tcc.setRmiRegistryPort(10800);

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
	  tcc.setHttpPort(Integer.valueOf(st.nextToken()).intValue());
	  // Get HTTPS port number
	  if (!st.hasMoreTokens()) {
	    throw new RuntimeException("Incorrect configuration file. Expected HTTPS port number");
	  }
	  tcc.setHttpsPort(Integer.valueOf(st.nextToken()).intValue());

	  // Get RMI registry port number
	  if (!st.hasMoreTokens()) {
	    throw new RuntimeException("Incorrect configuration file. Expected RMI registry port number");
	  }
	  tcc.setRmiRegistryPort(Integer.valueOf(st.nextToken()).intValue());
	}
      }
      buffreader.close();
    }
    catch(FileNotFoundException fnotfoundexp) {
      Assert.fail("User parameter configuration file not found");
      fnotfoundexp.printStackTrace();
    }
    catch(IOException ioexp) {
      Assert.fail("Cannot read User parameter configuration file: " + ioexp);
      ioexp.printStackTrace();
    }
  }

  public void characters( char[] ch, int start, int length )
    throws SAXException {
    super.characters(ch, start, length);
    setContents();
  }

  private String contentsValue;
  public String getContents() {
    return (contentsValue == null ? null : contentsValue.trim());
  }

  protected void setContents() {
    contentsValue = parseContents(contents.toString());
  }

  private class MyStack
    extends Stack {
    public Object peek() {
      Object o = super.peek();
      SaxMapperLog.trace("Peek object:" + o.getClass().getName() + " : " + o.toString());
      return o;
    }
    public Object pop() {
      Object o = super.pop();
      SaxMapperLog.trace("Pop object:" + o.getClass().getName() + " : " + o.toString());
      return o;
   }
    public Object push(Object o) {
      Object o1 = super.push(o);
      SaxMapperLog.trace("Push object:" + o.getClass().getName() + " : " + o.toString());
      return o1;
   }
  }

}
