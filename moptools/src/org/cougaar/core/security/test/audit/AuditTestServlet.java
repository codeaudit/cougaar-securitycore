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


package org.cougaar.core.security.test.audit;


import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.audit.AuditLogger;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.servlet.BaseServletComponent;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;


/**
 * Simple Servlet that searches AudtiRecords for  the audit event for accessing
 * this servlet.  This assumes that the infrastructure is already logging all
 * access to Servlet Resources.  You will have to give this class permission
 * to read the audit logs when running in Secure Mode!
 *
 * @author ttschampel
 * @version $Revision: 1.2 $
 */
public class AuditTestServlet extends BaseServletComponent {
  private String agentName;
  private LoggingService logging = null;

  /**
   * Get Path to this Servlet
   *
   * @return <code>/testAuditServlet</code>
   */
  protected String getPath() {
    return "/testAuditServlet";
  }


  /**
   * Get AgentIdentifier Service
   */
  public void load() {
    super.load();
    AgentIdentificationService agentIdService = (AgentIdentificationService) this.serviceBroker
      .getService(this, AgentIdentificationService.class, null);
    agentName = agentIdService.getMessageAddress().getAddress();
    logging = (LoggingService) this.serviceBroker.getService(this,
        LoggingService.class, null);
  }


  /**
   * Create Servlet
   *
   * @return TestServlet
   */
  protected Servlet createServlet() {
    return new TestServlet();

  }

  private class TestServlet extends HttpServlet {
    /**
     * Simply does a search on the audit web access log for  the access event
     * generated for access this servlet.
     *
     * @param request HTTP Request
     * @param response HTTP Response
     */
    protected void execute(HttpServletRequest request,
      HttpServletResponse response) {
      String responseString = "FALSE";
      if (logging.isDebugEnabled()) {
        logging.debug("Testing audit service");

      }

      //wait for 5 seconds to give time for logger to log event
      long timeMillis = System.currentTimeMillis();
      while (System.currentTimeMillis() >= (timeMillis + 5000)) {
        //do nothing
      }

      //check log records 
      String auditDirectory = AuditLogger.getLoggingDirectory();
      String fileName = auditDirectory + File.separator + "WebLog-"
        + System.getProperty("org.cougaar.node.name") + ".txt.0";
      if(logging.isDebugEnabled()){
      	logging.debug("Reading audit file:" + fileName);
      }
      long minTime = (timeMillis - 30000);
      long maxTime = (timeMillis + 30000);
      try {
        File f = new File(fileName);
        BufferedReader reader = new BufferedReader(new FileReader(f));
        StringBuffer recordBuffer = new StringBuffer();
        String dataLine = reader.readLine();
        long _timestamp = 0;
        String _servletName = null;
        String _agentName = null;
        while (dataLine != null) {
         if(dataLine.indexOf("<record>")>=0){
         	_timestamp=0;
         	_agentName=null;
         	_servletName=null;
         }
          if (dataLine.indexOf("<timestamp>") >= 0) {
            String timeStampStr = dataLine.substring(dataLine.indexOf(
                  "<timestamp>") + 11, dataLine.indexOf("</timestamp"));
            _timestamp = Long.parseLong(timeStampStr);

          }

          if (dataLine.indexOf("<agent>") >= 0) {
            _agentName = dataLine.substring(dataLine.indexOf("<agent>") + 7,
                dataLine.indexOf("</agent>"));
          }

          if (dataLine.indexOf("<servlet>") >= 0) {
            _servletName = dataLine.substring(dataLine.indexOf("<servlet>") + 9,
                dataLine.indexOf("</servlet>"));
          }
		  if(logging.isDebugEnabled()){
		  	logging.debug("Found:" + _timestamp +","+_servletName+","+_agentName);
		  	logging.debug("Required:" + minTime+":"+maxTime+",testAuditServlet," + agentName);
		  }
          if (((_timestamp >= minTime) && (_timestamp <= maxTime))
            && (_servletName!=null && _servletName.equals("testAuditServlet")) &&(_agentName!=null && _agentName.equals(agentName))) {
            responseString = "TRUE";
            dataLine = null;
          } else {
            dataLine = reader.readLine();
          }
        }

        reader.close();
      } catch (Exception e) {
        if (logging.isErrorEnabled()) {
          logging.error("Error accessing audit log", e);
        }
      }

      try {
        PrintWriter out = response.getWriter();
        out.println(responseString);
        out.close();
        if (logging.isDebugEnabled()) {
          logging.debug("Audit log check:" + responseString);
        }
      } catch (Exception e) {
        if (logging.isErrorEnabled()) {
          logging.error("Error writing audit check response to response", e);
        }
      }
    }


    public void doGet(HttpServletRequest request, HttpServletResponse response) {
      doPost(request, response);
    }


    public void doPost(HttpServletRequest request, HttpServletResponse response) {
      execute(request, response);
    }
  }
}
