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

public class ConfigHandler
  extends DefaultHandler
{
  // XML Parser
  protected XMLReader parser;

  private Hashtable attributeTable;
  private boolean replaceJavaProperties = true;
  private boolean replaceAttributes = true;

  private String junitConfigPath;
  private String userName;

  private NodeConfiguration currentNodeConf;
  private ArrayList nodeConfList;

  // Buffer for collecting data from
  // the "characters" SAX event.
  protected CharArrayWriter contents = new CharArrayWriter();

  public ConfigHandler(XMLReader parser) {
    this.parser = parser;
    nodeConfList = new ArrayList();

    junitConfigPath = System.getProperty("org.cougaar.junit.config.path");
    Assert.assertNotNull("Unable to get org.cougaar.junit.config.path", junitConfigPath);

    userName = System.getProperty("user.name");
    Assert.assertNotNull("Unable to get user name", userName);

    replaceJavaProperties(true);
  }

  public ArrayList getNodeConfigurationList() {
    return nodeConfList;
  }

  public static final String NODE_TEST = "nodeTest";
  public static final String HOW_LONG = "howLongBeforeStart";
  public static final String MAX_EXEC_TIME = "maxExecTime";
  public static final String HOST_NAME = "hostName";
  public static final String NODE_STARTUP_DIRECTORY = "nodeStartupDirectory";
  public static final String PROPERTY_FILE = "propertyFile";
  public static final String ARGUMENTS = "arguments";

  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attr )
    throws SAXException {
    contents.reset();

    if (localName.equals(NODE_TEST)) {
      System.out.println("New nodeTest");
      currentNodeConf = new NodeConfiguration("");

      // Set top-level directory
      File f1 = new File(System.getProperty("org.cougaar.securityservices.base"));
      String top = f1.getAbsolutePath();
      currentNodeConf.setTopLevelDirectory(top);

      // Set user parameters
      setUserParameters(currentNodeConf);

      nodeConfList.add(currentNodeConf);
    }
  }

  public void endElement( String namespaceURI,
			  String localName,
			  String qName )
    throws SAXException {
    String value = getContents();

    System.out.println("Element:" + localName + " - value: " + value);

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
    else if (localName.equals(NODE_STARTUP_DIRECTORY)) {
      currentNodeConf.setNodeStartupDirectoryName(currentNodeConf.getTopLevelDirectory()
						  + File.separator + value);
    }
    else if (localName.equals(PROPERTY_FILE)) {
      currentNodeConf.setPropertyFile(value);
    }
    else if (localName.equals(ARGUMENTS)) {
      ArrayList argsList = new ArrayList();
      StringTokenizer st = new StringTokenizer(value);
      while (st.hasMoreTokens()) {
	argsList.add(st.nextToken());
      }
      String[] args = (String[]) argsList.toArray(new String[1]);
      currentNodeConf.setNodeArguments(args);
    }
  }

  public void characters( char[] ch, int start, int length )
    throws SAXException {
    contents.write(ch, start, length);
    setContents();
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

  public String getContents() {
    return (contentsValue == null ? null : contentsValue.trim());
  }

  private String contentsValue;

  protected void setContents() {
    contentsValue = parseContents(contents.toString());
  }

  protected String parseContents(String s) {
    Pattern p_javaprop = Pattern.compile("\\$\\{.*\\}");
    Pattern p_keyvalue = Pattern.compile("\\$\\[.*\\]");
    Matcher matcher = null;
    StringBuffer sb = new StringBuffer();
    boolean result = false;


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
	String propertyValue = System.getProperty(propertyName);
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
    
    return s;
  }

  private void setUserParameters(NodeConfiguration tcc) {
    File userParamFile = new File(junitConfigPath + File.separator + "userParameters.conf");
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
 
}

