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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;
import java.io.PrintWriter;


/**
 * Simple Servlet that searches AudtiRecords for  the audit event for accessing
 * this servlet.  This assumes that the infrastructure is already logging all
 * access to Servlet Resources.  You will have to give this class permission
 * to read the audit logs when running in Secure Mode!
 *
 * @author ttschampel
 * @version $Revision: 1.3 $
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


    private boolean checkLogFile(String fileName, long timeMillis,
        String agentName, String servletName) {
        boolean foundIt = false;
        long minTime = (timeMillis - 30000);
        long maxTime = (timeMillis + 30000);
        try {
            Object[] src = new Object[2];
            src[0] = new File(fileName);
            src[1] = "</log>\r\n";
            XMLFragmentReader fr = new XMLFragmentReader(src, System.out);
            Document dom = fr.build();
            if (dom == null) {
            	System.err.println("" + fr.lastErr);
                if (logging.isErrorEnabled()) {
                    logging.error("Error parsing log file");
                }
            } else {
                NodeList recordList = dom.getDocumentElement()
                                         .getElementsByTagName("record");
                for (int i = 0; i < recordList.getLength(); i++) {
                    if (foundIt == true) {
                        break;
                    }

                    Element recordNode = (Element) recordList.item(i);
                    NodeList timestampList = recordNode.getElementsByTagName(
                            "timestamp");
                    NodeList agentList = recordNode.getElementsByTagName(
                            "agent");
                    NodeList servletList = recordNode.getElementsByTagName(
                            "servlet");
                    if ((timestampList.getLength() > 0)
                        && (agentList.getLength() > 0)
                        && (servletList.getLength() > 0)) {
                        Node agentNode = agentList.item(0);
                        Node servletNode = servletList.item(0);
                        Node timeNode = timestampList.item(0);
                        String _agentName = agentNode.getFirstChild()
                                                     .getNodeValue();
                        long _timestamp = Long.parseLong(timeNode.getFirstChild()
                                                                 .getNodeValue());
                        String _servletName = servletNode.getFirstChild()
                                                         .getNodeValue();
                        if (logging.isDebugEnabled()) {
                            logging.debug("Found:" + _timestamp + ","
                                + _servletName + "," + _agentName);
                            logging.debug("Required:" + minTime + ":" + maxTime
                                + ","+servletName+"," + agentName);
                        }

                        if (((_timestamp >= minTime) && (_timestamp <= maxTime))
                            && ((_servletName != null)
                            && _servletName.equals(servletName))
                            && ((_agentName != null)
                            && _agentName.equals(agentName))) {
                            foundIt = true;
                            break;
                        }
                    }
                }
            }
        } catch (Exception e) {
            if (logging.isErrorEnabled()) {
                logging.error("Error accessing audit log", e);
            }
        }

        return foundIt;
    }
	
	public static void main(String args[]){
		String fileName = args[0];
		String agentName = args[1];
		String timeString = args[2];
		String servletName = args[3];
		long timeStamp = Long.parseLong(timeString);
		
		AuditTestServlet ts = new AuditTestServlet();
		boolean foundIt = ts.checkLogFile(fileName, timeStamp, agentName, servletName);
		System.out.println("Found it:" + foundIt);
	}
	
    private class TestServlet extends HttpServlet {
        /**
         * Simply does a search on the audit web access log for  the access
         * event generated for access this servlet.
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
            if (logging.isDebugEnabled()) {
                logging.debug("Reading audit file:" + fileName);
            }

            boolean logged = checkLogFile(fileName, timeMillis, agentName,"/testAuditServlet");
            if (logged) {
                responseString = "TRUE";
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
                    logging.error("Error writing audit check response to response",
                        e);
                }
            }
        }


        public void doGet(HttpServletRequest request,
            HttpServletResponse response) {
            doPost(request, response);
        }


        public void doPost(HttpServletRequest request,
            HttpServletResponse response) {
            execute(request, response);
        }
    }
}
