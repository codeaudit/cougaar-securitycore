/*
 * <copyright>
 *  Copyright 2002-2003 Cougaar Software, Inc.
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
 */
package org.cougaar.core.security.test;

// java packages

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.adaptivity.*;
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.community.AgentImpl;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.servlet.ComponentServlet;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.util.UID;

/**
 * SendOperatingModeServlet will publish an InterAgentOperatingMode to
 * constrain a remote condition.  The InterAgentOperatingMode is published
 * as an InterAgentCondition on the target side.
 */
public class SendOperatingModeServlet extends ComponentServlet 
  implements BlackboardClient {

    /** Logging Service */
    private LoggingService _log;
   
    private UIDService _uidService;
    private BlackboardService _blackboardService;
    private final OMCRangeList OMRANGE = 
      new OMCRangeList(new Double(0.0), new Double(Integer.MAX_VALUE));
      
    private HashMap _relays = new HashMap();
    
    public void setLoggingService(LoggingService service) {
      if(_log != null) {
        _log = service;
      }
    }

    public void setUIDService(UIDService service) {
      if(_uidService != null) {
        _uidService = service;
      }
    }

    public void setBlackboardService(BlackboardService service) {
      if(_blackboardService != null) {
        _blackboardService = service;
      } 
    }

    public String getBlackboardClientName() {
      return getPath(); 
    }

  protected String getPath() {
    return "/sendOperatingModeServlet";
  }


    public long currentTimeMillis() {
      return -1; // not used 
    }

    public void unload() {
      // release all services and do any clean up
      if(serviceBroker != null) {
        if(_blackboardService != null) {
          serviceBroker.releaseService(this, BlackboardService.class, _blackboardService);
        }
        if(_uidService != null) {
          serviceBroker.releaseService(this, UIDService.class, _uidService);
        }
        if(_log != null) {
          serviceBroker.releaseService(this, LoggingService.class, _log);
        }
      }
      super.unload();
    }
    
    public void service(HttpServletRequest req, HttpServletResponse resp) 
    throws IOException {
      String agent = req.getParameter("agent");
      String modeName = req.getParameter("modeName");
      String modeValue = req.getParameter("modeValue");
      if(_blackboardService == null) {
        _blackboardService = (BlackboardService)
          serviceBroker.getService(this, BlackboardService.class, null);
      }
      if(agent == null || modeName == null || modeValue == null) {
        printForm(resp);
        return;
      }
     
      // construct an InterAgentOperatingMode
      InterAgentOperatingMode iaom = getIAOM(agent, modeName, modeValue);
      // publish the InterAgentOperatingMode to the blackboard
      _blackboardService.openTransaction();
      _blackboardService.publishAdd(iaom);
      _blackboardService.closeTransaction();
      printResponse(resp, iaom);
    }
  
    private InterAgentOperatingMode getIAOM(String agent, String modeName, String modeValue) {
      HashMap modes = null;
      InterAgentOperatingMode mode = null;
      synchronized(_relays) {
        modes = (HashMap)_relays.get(agent);
        if(modes == null) {
          modes = new HashMap(); 
          mode = constructIAOM(agent, modeName, modeValue);
          modes.put(modeName, mode);
          _relays.put(agent, modes);
        } else {
          mode = (InterAgentOperatingMode)modes.get(modeName);
          if(mode != null) {
            mode.setValue(new Double(modeValue));
          } else {
            mode = constructIAOM(agent, modeName, modeValue);
            modes.put(modeName, mode);
          }
        }
      }
      return mode;
    }
    private InterAgentOperatingMode constructIAOM(String agent, String modeName, String modeValue) {
      InterAgentOperatingMode iaom = new InterAgentOperatingMode(modeName, OMRANGE, new Double(modeValue));
      iaom.setUID(getUID());
      iaom.setTarget(MessageAddress.getMessageAddress(agent));
      return iaom;
    }
    
    private UID getUID() {
      if(_uidService == null) {
        _uidService = (UIDService)serviceBroker.getService(this, UIDService.class, null);
      }
      return (_uidService != null ? _uidService.nextUID() : null);
    }

    public void printForm(HttpServletResponse resp) throws IOException {
      PrintWriter out = resp.getWriter();
      resp.setContentType("text/html");
      out.println("<html>\n" +
                  "<head><title>Send InterAgentOperatingMode Servlet</title></head>\n" +
                  "<body><h1>Send InterAgentOperatingMode Servlet</h1>\n" +
                  "<form action=\"\">\n" +
                  "Agent name: <input type=\"text\" name=\"agent\" " +
                  "value=\"ConusEnclaveMnRManager\" size=\"50\">\n<br>" +
                  "Condition name: <input type=\"text\" name=\"modeName\" " +
                  "value=\"org.cougaar.core.security.monitoring.LOGIN_FAILURE_RATE\" size=\"80\">\n<br>" +
                  "Condition value: <input type=\"text\" name=\"modeValue\" " +
                  "value=\"\">\n<br>" +
                  "<input type=\"submit\"></form></body></html>\n");
      out.close();
    }
  
    public void printResponse(HttpServletResponse resp, InterAgentOperatingMode iaom) throws IOException {
      PrintWriter out = resp.getWriter();
      resp.setContentType("text/html");
      out.println("<html>\n" +
                  "<head><title>Send InterAgentOperatingMode Servlet</title></head>\n" +
                  "<body><h1>Published InterAgentOperatingMode</h1>\n" +
                  "<br> <b>Source Agent:</b> " + getAgentIdentifier() + 
                  "<br> <b>Target Agent:</b> " + iaom.getTargets().iterator().next() + 
                  "<br> <b>OperatingMode Name:</b> " + iaom.getName() +
                  "<br> <b>OperatingMode Value:</b> " + iaom.getValue() + 
                  "</body></html>\n");
      out.close();
    }
}
