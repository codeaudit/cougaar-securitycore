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
import java.net.Socket;
import java.net.ServerSocket;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;
import java.text.*;
import java.lang.reflect.Constructor;

import junit.framework.*;

import org.cougaar.util.ConfigFinder;
import org.cougaar.bootstrap.XURLClassLoader;

import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.apache.xerces.parsers.DOMParser;

import org.apache.log4j.*;
import org.apache.log4j.net.*;
import org.apache.log4j.spi.*;
import org.apache.log4j.or.RendererMap;
import org.apache.log4j.helpers.*;
import org.apache.log4j.xml.*;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

public class Log4jSocketServer
{
  public static void main(String[] args) {
    try {
      NodeConfiguration[] nc = new NodeConfiguration[2];
      nc[0] = new NodeConfiguration();
      nc[0].setNodeName("firstNode");
      nc[1] = new NodeConfiguration();
      nc[1].setNodeName("secondNode");
      Log4jSocketServer s = new Log4jSocketServer();
      int port = Integer.valueOf(args[0]).intValue();

      s.startLog4jSocketServer(port, nc[0]);
      port++;
      s.startLog4jSocketServer(port, nc[1]);
    }
    catch (Exception e) {
      System.out.println("Exception: " + e);
      e.printStackTrace();
    }
  }

  public Log4jSocketServer() {
    Object guard = new Object();
    LogManager.setRepositorySelector(new LogSelector(), guard);
  }

  public void startLog4jSocketServer(final int portNumber, final NodeConfiguration nc) {
    System.out.println("Starting simple socket server thread on port " + portNumber);
    Thread socketServer = new Thread() {
	public void run() {
	  String junitConfigPath =
	    System.getProperty("org.cougaar.junit.config.path");
	  Assert.assertNotNull("Unable to get org.cougaar.junit.config.path",
			       junitConfigPath);
	  String configFile = junitConfigPath + File.separator + "loggingConfig.xml";
	  System.out.println("Starting simple socket server on port "
			     + portNumber  + " " + configFile);
	  Document doc = parseConfiguration(configFile);
	  customizeLog4jConfiguration(doc, nc);
	  try {
	    DOMConfigurator.configure(doc.getDocumentElement());
	    startServer(portNumber);
	  }
	  catch (Exception e) {
	    System.err.println("Unable to load class " + e);
	    e.printStackTrace();
	  }
	}

	private void startServer(int port) {
	  try {
	    Category cat = Category.getInstance(Log4jSocketServer.class.getName());

	    cat.info("Listening on port " + port);
	    ServerSocket serverSocket = new ServerSocket(port);
	    while(true) {
	      cat.info("Waiting to accept a new client.");
	      Socket socket = serverSocket.accept();
	      cat.info("Connected to client at " + socket.getInetAddress());
	      cat.info("Starting new socket node.");
	      new Thread(new SocketNode(socket,
					LogManager.getLoggerRepository())).start();
	    }
	  } catch(Exception e) {
	    e.printStackTrace();
	  }
	}

      };
    socketServer.start();
  }

  protected void customizeLog4jConfiguration(Document doc, NodeConfiguration nc) {

    // Select a unique file name for every node.
    NodeList nl = doc.getElementsByTagName("param");
    for (int i = 0 ; i < nl.getLength() ; i++) {
      Node node = nl.item(i);
      if (node instanceof Element) {
	Element element = (Element) node;
	Node parent = node.getParentNode();
	//System.out.println(element.toString());
	if (parent.getNodeName().equals("appender") &&
	    element.getAttribute("name").equals("File")) {
	  Attr value = element.getAttributeNode("value");
	  element.removeAttributeNode(value);
	  File f = new File(value.getValue());
	  String fileName = f.getPath();
	  fileName = fileName.substring(0, fileName.lastIndexOf("."))
	    + "-" + nc.getNodeName() +
	    fileName.substring(fileName.lastIndexOf("."));
	  fileName = System.getProperty("junit.test.result.path") + 
	    File.separator + nc.getNodeName() + File.separator + fileName;
	  /*
	  if (f.getParent() != null) {
	    fileName = f.getParent() + File.separator + fileName;
	  }
	  */
	  System.out.println("Log file name: " + fileName);
	  value.setValue(fileName);
	  element.setAttributeNode(value);
	}
      }
    }
  }

  final static String dbfKey = "javax.xml.parsers.DocumentBuilderFactory";

  /*
  protected Document parseConfiguration(String filename)
    throws FactoryConfigurationError {
    Document doc = null;
    try {
      FileInputStream fis = null;
      fis = new FileInputStream(filename);
      InputSource inputSource = new InputSource(fis);
      DocumentBuilderFactory dbf = null;

      dbf = DocumentBuilderFactory.newInstance();
      System.out.println("Standard DocumentBuilderFactory search succeded.");
      System.out.println("DocumentBuilderFactory is: "+dbf.getClass().getName());

      // This makes ID/IDREF attributes to have a meaning. Don't ask
      // me why.
      dbf.setValidating(true);
      //dbf.setNamespaceAware(true);
 
      DocumentBuilder docBuilder = dbf.newDocumentBuilder();
      docBuilder.setErrorHandler(new SAXErrorHandler());
 
      Class clazz = this.getClass();
      URL dtdURL = clazz.getResource("/org/apache/log4j/xml/log4j.dtd");
      if(dtdURL == null) {
        System.err.println("Could not find [log4j.dtd]. Used ["+clazz.getClassLoader()+
                     "] class loader in the search.");
      }
      else {
        System.out.println("URL to log4j.dtd is [" + dtdURL.toString()+"].");
        inputSource.setSystemId(dtdURL.toString());
      }
      doc = docBuilder.parse(inputSource);
    } catch (Exception e) {
      System.err.println("Could not parse input source ["+filename+"]." + e);
      e.printStackTrace();
    }
    return doc;
  }
  */

  protected Document parseConfiguration(String filename) {
    Document doc = null;
    DOMParser parser = new DOMParser();
    try {
      FileInputStream fis = null;
      fis = new FileInputStream(filename);
      InputSource inputSource = new InputSource(fis);
 
      Class clazz = this.getClass();
      URL dtdURL = clazz.getResource("/org/apache/log4j/xml/log4j.dtd");
      if(dtdURL == null) {
        System.err.println("Could not find [log4j.dtd]. Used ["+clazz.getClassLoader()+
                     "] class loader in the search.");
      }
      else {
        System.out.println("URL to log4j.dtd is [" + dtdURL.toString()+"].");
        inputSource.setSystemId(dtdURL.toString());
      }
      parser.parse(inputSource);

    } catch (Exception e) {
      System.err.println("Could not parse input source ["+filename+"]." + e);
      e.printStackTrace();
    }
    return parser.getDocument();
  }

}
