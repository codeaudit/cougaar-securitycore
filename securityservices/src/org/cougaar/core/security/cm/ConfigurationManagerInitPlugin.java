/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


/*
 * Created on Jul 29, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.cougaar.core.security.cm;


import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.cougaar.core.component.ComponentDescription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.UIDService;
import org.cougaar.util.ConfigFinder;
import org.cougaar.util.UnaryPredicate;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

import java.io.CharArrayWriter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;


/**
 * Creates the SocietyConfiguration representation for time t0. For now,
 * configuration is retreived from the "society.xml" file.  For now, society
 * configuration is persisted to the blackboard.
 *
 * @author ttschampel
 */
public class ConfigurationManagerInitPlugin extends ComponentPlugin {
  //Plugin Constants
  private static final String PLUGIN_NAME = "ConfigurationManagerInitPlugin";
  private static final String CSMART_DRIVER = "driver.mysql";
  private static final String CSMART_URL = "org.cougaar.configuration.database";
  private static final String CSMART_USERNAME = "org.cougaar.configuration.user";
  private static final String CSMART_PASSWORD = "org.cougaar.configuration.password";
  /** Logging Service */
  private LoggingService logger = null;
  /** UIDService */
  private UIDService uidService = null;
  private String filename;
  private String nodename;
  HashMap agentMap = new HashMap();
  /** Society Configuration Value object */
  private SocietyConfiguration societyConfiguration;
  /** Predicate for SocietyConfiguration */
  private UnaryPredicate societyConfigurationPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        return o instanceof SocietyConfiguration;
      }
    };

  /**
   * Setup the Logging Service
   *
   * @param service LoggingService
   */
  public void setLoggingService(LoggingService service) {
    this.logger = service;
  }


  /**
   * Set UIDService
   *
   * @param service DOCUMENT ME!
   */
  public void setUIDService(UIDService service) {
    this.uidService = service;
  }


  /**
   * Component Load method
   */
  public void load() {
    super.load();
    filename = System.getProperty("org.cougaar.society.file");
    nodename = System.getProperty("org.cougaar.node.name");

  }


  /**
   * Setup subscriptions (none) and get t0 society configuration
   */
  public void setupSubscriptions() {
    if (logger.isDebugEnabled()) {
      logger.debug(PLUGIN_NAME + " setupSubscriptions()");
    }

    if (getBlackboardService().didRehydrate()) {
      //get society configuration from blackboard
      if (logger.isDebugEnabled()) {
        logger.debug("Getting Society configuration from blackboard");

      }

      Collection coll = getBlackboardService().query(societyConfigurationPredicate);
      Iterator iter = coll.iterator();
      int index = 0;
      while (iter.hasNext()) {
        index++;
        this.societyConfiguration = (SocietyConfiguration) iter.next();
      }

      if (index == 0) {
        if (logger.isErrorEnabled()) {
          logger.error("No SocietyConfiguration on the blackboard!");
        }
      }

      if (this.societyConfiguration != null) {
        getBlackboardService().publishChange(societyConfiguration);
      }
    } else {
      try {
        agentMap = new HashMap();
        parseFile();
        if (logger.isDebugEnabled()) {
          logger.debug("Done parsing XML file");
        }

        HashMap agentList = new HashMap();
        Set agentSet = agentMap.keySet();
        Iterator agentIterator = agentSet.iterator();
        while (agentIterator.hasNext()) {
          String agent = (String) agentIterator.next();
          ArrayList nodes = (ArrayList) agentMap.get(agent);
          AgentConfiguration agentConfiguration = new AgentConfiguration(agent,
              nodes);
          if (logger.isDebugEnabled()) {
            logger.debug("Adding agent " + agent
              + " details to configuration manager");
          }

          agentList.put(agent, agentConfiguration);
        }


        societyConfiguration = new SocietyConfiguration(agentList);
        societyConfiguration.setUID(uidService.nextUID());
      } catch (Exception e) {
        if (logger.isErrorEnabled()) {
          logger.error("Error getting society configuration from xml", e);
        }
      }

      if (this.societyConfiguration != null) {
        getBlackboardService().publishAdd(this.societyConfiguration);
      }
    }
  }


  /**
   * No implmentation for now...
   */
  public void execute() {
    if (logger.isDebugEnabled()) {
      logger.debug(PLUGIN_NAME + " executing");
    }
  }


  /**
   * DOCUMENT ME!
   *
   * @param insertionPoint
   *
   * @return
   */
  private static String insertionPointContainer(String insertionPoint) {
    return insertionPoint.substring(0, insertionPoint.lastIndexOf('.'));
  }


  /**
   * Parse Society XML File
   *
   * @throws FileNotFoundException
   * @throws IOException
   * @throws SAXException
   * @throws ParserConfigurationException
   */
  private void parseFile()
    throws FileNotFoundException, IOException, SAXException, 
      ParserConfigurationException {
    MyHandler handler = new MyHandler();
    SAXParserFactory factory = SAXParserFactory.newInstance();
    factory.setValidating(Boolean.getBoolean("org.cougaar.core.node.validate"));
    if (logger.isDebugEnabled()) {
      logger.debug((factory.isValidating()) ? "Validating against schema"
                                            : "Validating disabled");
    }

    factory.setNamespaceAware(true);
    SAXParser saxParser = factory.newSAXParser();


    // Uncomment the following line when we go back to xerces2 again - bug 2823
    //    saxParser.setProperty(JAXP_SCHEMA_LANGUAGE, W3C_XML_SCHEMA);
    InputStream istr = ConfigFinder.getInstance().open(filename);
    if (istr == null) {
      logger.error("null InputStream from ConfigFinder on " + filename);
      return;
    }

    InputSource is = new InputSource(istr);
    if (is != null) {
      saxParser.parse(is, handler);
    } else {
      logger.error("Unable to open " + filename + " for XML initialization");
    }
  }

  /**
   * DOCUMENT ME!
   *
   * @author ttschampel
   */
  private class MyHandler extends DefaultHandler {
    Map currentComponent;
    String currentParent;
    CharArrayWriter chars;
    private final String stdPriority = ComponentDescription.priorityToString(ComponentDescription.PRIORITY_STANDARD);

    public void startElement(String namespaceURI, String localName,
      String qName, Attributes atts) throws SAXException {
      if (localName.equals("node")) {
        String thisName = atts.getValue("name");

        if (logger.isDebugEnabled()) {
          logger.debug("started element for node: " + thisName);
        }

        currentParent = thisName;


      }


      if (localName.equals("agent")) {
        String name = atts.getValue("name");
        if (logger.isDebugEnabled()) {
          logger.debug("started element for agent " + name);
        }

        ArrayList nodeList = null;
        agentMap.put(name, nodeList);
        Object obj = agentMap.get(name);
        if (obj == null) {
          nodeList = new ArrayList();

        } else {
          nodeList = (ArrayList) obj;
        }

        nodeList.add(currentParent);
        agentMap.put(name, nodeList);

      } else if (localName.equals("argument")) {
      	if(currentComponent!=null && chars==null){
        	chars = new CharArrayWriter();
      	}
      }
    }


    /**
     * @see org.xml.sax.ContentHandler#characters(char[], int, int)
     */
    public void characters(char[] ch, int start, int length)
      throws SAXException {
      if (chars != null) {
        chars.write(ch, start, length);
      }
    }


    /**
     * @see org.xml.sax.ErrorHandler#error(SAXParseException)
     */
    public void error(SAXParseException exception)
      throws SAXException {
      logger.error("Error parsing the file", exception);
      super.error(exception);
    }


    /**
     * @see org.xml.sax.ErrorHandler#warning(SAXParseException)
     */
    public void warning(SAXParseException exception)
      throws SAXException {
      logger.warn("Warning parsing the file", exception);
      super.warning(exception);
    }
  }
}
