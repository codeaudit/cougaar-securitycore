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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;
import java.util.StringTokenizer;

import junit.framework.Assert;

public class PropertyFile
{
  private String cip;
  private String userName;

  private String javaBin;
  private String mainClassName;
  private ArrayList properties;
  /** Environment variables when launching a node. */
  private String environmentVariables[];

  /** A hasbtable that describes whether a java property has already been set or not. */
  private Hashtable propertyStatus;

  public PropertyFile() {
    properties = new ArrayList();
    propertyStatus = new Hashtable();

    cip = System.getProperty("org.cougaar.install.path");
    Assert.assertNotNull("Unable to get COUGAAR_INSTALL_PATH", cip);

    userName = System.getProperty("user.name");
    Assert.assertNotNull("Unable to get user name", userName);

  }

  public String getJavaBin() {
    return javaBin;
  }
  public String getMainClassName() {
    return mainClassName;
  }

  public ArrayList getProperties() {
    return properties;
  }
  public String[] getEnvironmentVariables() {
    return environmentVariables;
  }

  public synchronized Properties readCustomPropertiesFile() {
    System.out.println("Reading custom property file...");
    String junitConfigPath = System.getProperty("org.cougaar.junit.config.path");
    Assert.assertNotNull("Unable to get org.cougaar.junit.config.path", junitConfigPath);

    File f = new File(junitConfigPath + File.separator + "junit.props");
    Properties props = System.getProperties();

    // Now, override with values found in file.
    try {
      FileReader filereader=new FileReader(f);
      BufferedReader buffreader=new BufferedReader(filereader);
      String linedata=new String();

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
	  propertyValue = st.nextToken();
	}
	System.out.println("Custom property: "  + property + "=" + propertyValue);
	props.put(property, propertyValue);
      }
    }
    catch(FileNotFoundException fnotfoundexp) {
      Assert.fail("Custom parameter configuration file not found");
    }
    catch(IOException ioexp) {
      Assert.fail("Cannot read Custom parameter configuration file: " + ioexp);
    }
    return props;
  }

  /**
   *  Read a configuration file containing java properties
   *  @param tcc the configuration of a Cougaar node.
   *  @param socketLogPort the port number of a log4j socket appender.
   */
  public synchronized void readPropertiesFile(NodeConfiguration tcc,
					      int socketLogPort) {
    File f = findPropertiesFile(tcc.getPropertyFile());
    if (f == null) {
      Assert.fail("Property file does not exist");
    }
    ArrayList env = new ArrayList();

    // Default values
    javaBin = "java";

    try {
      FileReader filereader=new FileReader(f);
      BufferedReader buffreader=new BufferedReader(filereader);
      String linedata=new String();

      Properties unparsedProperties = new Properties();

      // Read file properties
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
	String propertyValue = "";
	if (st.hasMoreTokens()) {
	  propertyValue = st.nextToken();
	}
	unparsedProperties.setProperty(property, propertyValue);
      }

      // Now, add (and potentially override) properties defined
      // in the XML experiment file.
      Properties props = tcc.getAdditionalVmProperties();
      Enumeration enum = props.propertyNames();
      while (enum.hasMoreElements()) {
	String key = (String) enum.nextElement();
	String val = props.getProperty(key);
        unparsedProperties.setProperty(key, val);
      }

      // Override Log4j configuration parameters
      if (tcc.getLog4jLogFile() == null) {
	System.err.println("Log4j log file is not set for "
	  + tcc.getNodeName());
      }
      unparsedProperties.setProperty("org.cougaar.core.logging.log4j.appender.SECURITY.File",
				     tcc.getLog4jLogFile());
      unparsedProperties.setProperty("org.cougaar.core.logging.log4j.appender.JUNITSOCKET.port",
				     String.valueOf(socketLogPort));    

      // Now, customize and parse the properties
      enum = unparsedProperties.propertyNames();
      while (enum.hasMoreElements()) {
	String key = (String) enum.nextElement();
	String value = unparsedProperties.getProperty(key);
	value = customizeProperty(value, tcc);

	if (key.startsWith("env.")) {
	  // Environment variable
	  key = key.substring(4);
	  String ev = key + "=" + value;
	  env.add(ev);
	}
	else if (key.equals("java.jvm.program")) {
	  javaBin = value;
	}
	else if (key.equals("java.class.name")) {
	  mainClassName = value;
	}
	else {
	  StringTokenizer st1 = new StringTokenizer(makeProperty(key, value, tcc));
	  while (st1.hasMoreTokens()) {
	    String arg = st1.nextToken();
	    properties.add(arg);
	  }
	}
      }

    }
    catch(Exception e) {
      e.printStackTrace();
      System.out.println("Unable to read configuration file for "
			 + tcc.getNodeName() + ": " + e);
      Assert.fail("Unable to read configuration file: " + e);
    }
    env.add("COUGAAR_INSTALL_PATH=" + System.getProperty("org.cougaar.install.path"));
    env.add("COUGAAR_WORKSPACE=" + System.getProperty("org.cougaar.workspace"));
    environmentVariables = (String[])env.toArray(new String[0]);
  }

  private String customizeProperty(String propertyValue, NodeConfiguration tcc) {
    String hostName = null;
    try {
      hostName = InetAddress.getLocalHost().getHostName();
    }
    catch (Exception e) {
      Assert.fail("Unable to get host name: " + e);
    }

    String convertFrom[] = {
      "/mnt/shared/integ",
      "asmt",
      "5557",
      "6557",
      "\\$HOSTNAME.log",
      "\\$HOSTNAME",
      "\""
      };

    String convertTo[] = {
      cip,
      userName,
      Integer.toString(tcc.getHttpPort()),
      Integer.toString(tcc.getHttpsPort()),
      tcc.getNodeName() + ".log",
      hostName,
      ""
    };

    for (int i = 0 ; i < convertFrom.length ; i++) {
      propertyValue = propertyValue.replaceAll(convertFrom[i], convertTo[i]);
    }
    return propertyValue;
  }

  private String makeProperty(String propertyName, String propertyValue,
			      NodeConfiguration tcc) {
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
	if (!propertyValue.equals("")) {
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
      String file = getCanonicalPath(cip + File.separator + "configs"
				     + File.separator + "security" 
				     + File.separator + "Linux.props");
      f = new File(file);
      System.out.print("Trying " + f.getPath() + "...");
      if (!f.exists()) {
	f = null;
	System.out.println(" Not found");
      }
      else {
	System.out.println(" Found");
      }
    }
    Assert.assertNotNull("Unable to find properties file", f);
    return f;
  }

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

}
