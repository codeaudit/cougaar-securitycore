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


package org.cougaar.core.security.test.javapolicy;


import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.DetectTime;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.test.AbstractServletComponent;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;

import java.util.ArrayList;


/**
 * A Servlet that is supposed to have access granted to the $CIP/workspace
 * directory. If it does not, then an IDMEF Event is published to the
 * blackboard.
 *
 * @author ttschampel
 */
public class AuthorizedResourceServlet extends AbstractServletComponent implements BlackboardClient {
  private static final String SERVLET_PATH = "/AuthorizedResourceServlet";

  /**
   * Get path to this servlet
   *
   * @return DOCUMENT ME!
   */
  protected String getPath() {
    return SERVLET_PATH;
  }


  /**
   * Process Http request, just try to access resource
   *
   * @param request DOCUMENT ME!
   * @param response DOCUMENT ME!
   */
  protected void execute(HttpServletRequest request, HttpServletResponse response) {
    try {
      String workspace = System.getProperty("org.cougaar.workspace");
      if (workspace == null) {
        if (logging.isErrorEnabled()) {
          logging.error("Workspace is null");
        }
      } else {
        File file = new File(workspace + File.separator + "authorizedTest");
        FileWriter writer = new FileWriter(file);
        writer.write("TEST");
        writer.close();
      }
    } catch (IOException se) {
      //create idmef event
      if (logging.isDebugEnabled()) {
        logging.debug("Could not access resource!");
      }

      createIdmefEvent();
    }
  }


  private void createIdmefEvent() {
    DetectTime detectTime = new DetectTime();
    detectTime.setIdmefDate(new java.util.Date());
    CmrFactory cmrFactory = (CmrFactory) this.domainService.getFactory("cmr");
    ArrayList classifications = new ArrayList();
    Classification c = (Classification) cmrFactory.getIdmefMessageFactory().createClassification("Could not access resource", null);
    classifications.add(c);
    Analyzer a = cmrFactory.getIdmefMessageFactory().createAnalyzer(new SensorInfo() {
        public String getName() {
          return this.getClass().getName();
        }


        public String getManufacturer() {
          return "CSI";
        }


        public String getModel() {
          return "JavaPolicyTool";
        }


        public String getVersion() {
          return "1.0";
        }


        public String getAnalyzerClass() {
          return "JavaResourceAccessControlPlugin";
        }
      });

    Alert alert = cmrFactory.getIdmefMessageFactory().createAlert(a, detectTime, null, null, classifications, null);
    if (logging.isInfoEnabled()) {
      logging.info("*****************************Publishing IDMEF Event");
    }

    Event event = cmrFactory.newEvent(alert);

    if (!(event instanceof Serializable)) {
      if (logging.isErrorEnabled()) {
        logging.error("Event is not serializable");
      }
    }

    this.blackboardService.openTransaction();
    this.blackboardService.publishAdd(event);
    this.blackboardService.closeTransaction();
  }
}
