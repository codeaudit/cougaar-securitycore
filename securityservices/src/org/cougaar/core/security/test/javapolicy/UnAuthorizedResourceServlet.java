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
import java.io.PrintWriter;
import java.io.IOException;
import java.io.Serializable;

import java.util.ArrayList;


/**
 * DOCUMENT ME!
 *
 * @version $Revision: 1.3 $
 * @author $author$
 */
public class UnAuthorizedResourceServlet extends AbstractServletComponent implements BlackboardClient {
  private static final String SERVLET_PATH = "/UnAuthorizedResourceServlet";

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
    PrintWriter out=response.getWriter();
    FileWriter writer = null;
    try {
      String cip = System.getProperty("org.cougaar.install.path");
      if (cip == null) {
        if (logging.isErrorEnabled()) {
          logging.error("cougaar install path is null");
        }
        out.println("FALSE");
      } else {
        File file = new File(cip + File.separator + "unauthorizedTest");
        writer = new FileWriter(file);
        writer.write("TEST");
        writer.close();
        //create idmef event
        if (logging.isDebugEnabled()) {
          logging.debug("Could access resource!");
        }
        out.println("FALSE");
        createIdmefEvent();
      }
    } catch (IOException se) {
      out.println("TRUE");
      //good
    } finally {
      try {
        writer.close();
      } catch (Exception e) {
      }
    }
    out.flush();
    out.close();
  }


  private void createIdmefEvent() {
    DetectTime detectTime = new DetectTime();
    detectTime.setIdmefDate(new java.util.Date());
    CmrFactory cmrFactory = (CmrFactory) this.domainService.getFactory("cmr");
    ArrayList classifications = new ArrayList();
    Classification c = (Classification) cmrFactory.getIdmefMessageFactory().createClassification("Could access resource", null);
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
