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
package org.cougaar.core.security.test.community;

// java packages

import java.io.IOException;
import java.io.PrintWriter;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.community.AgentImpl;
import org.cougaar.community.manager.Request;
import org.cougaar.community.manager.RequestImpl;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.servlet.ComponentServlet;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.util.UID;

/**
 * JoinCommunityServlet will publish a CommunityManager Request to
 * join an agent to a particular community. 
 */
public class JoinCommunityServlet extends ComponentServlet 
  implements BlackboardClient {

    /** Logging Service */
    private LoggingService _log;
   
    private UIDService _uidService;
    private BlackboardService _blackboardService;
    
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
      String community = req.getParameter("commmunity");
      String manager = req.getParameter("manager");
      if(_blackboardService == null) {
        _blackboardService = (BlackboardService)
          serviceBroker.getService(this, BlackboardService.class, null);
      }
      if(manager == null) {
        printForm(resp);
        return;
      }
      if(agent == null) {
        agent = getAgentIdentifier().toString();  // use this agent
      }
      if(community == null) {
        community = "MyTestCommunity";
      }    
      // construct a Request
      Request cmr = constructRequest(agent, community, manager);
      // publish the Request to the blackboard
      _blackboardService.openTransaction();
      _blackboardService.publishAdd(cmr);
      _blackboardService.closeTransaction();
      printResponse(resp, cmr);
    }
  
    private Request constructRequest(String agent, String community, 
      String manager) {
      Attributes roleAttributes = new BasicAttributes();
      roleAttributes.put(new BasicAttribute("Role", "Member"));
      roleAttributes.put(new BasicAttribute("EntityType", "Agent"));
      CommunityResponseListener crl = new CommunityResponseListener() {
        public void getResponse(CommunityResponse response) {
          if (_log.isDebugEnabled()) {
            _log.debug("Response listener invoked. Status=" +
                       response.getStatusAsString() + " - Content:" +
                       ((Entity)(response.getContent())).toXml());
          }
        }
      };
      return new RequestImpl(getAgentIdentifier(),
                             MessageAddress.getMessageAddress(manager),
                             community,
                             Request.JOIN,
                             new AgentImpl(agent, roleAttributes),
                             null,
                             getUID(),
                             crl);           
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
                  "<head><title>Join Community Servlet</title></head>\n" +
                  "<body><h1>Join Community Request</h1>\n" +
                  "<form action=\"\">\n" +
                  "Agent name: <input type=\"text\" name=\"agent\" " +
                  "value=\"\">\n<br>" +
                  "Community name: <input type=\"text\" name=\"community\" " +
                  "value=\"\">\n<br>" +
                  "Community manager: <input type=\"text\" name=\"manager\" " +
                  "value=\"\">\n<br>" +
                  "<input type=\"submit\"></form></body></html>\n");
      out.close();
    }
  
    public void printResponse(HttpServletResponse resp, Request r) throws IOException {
      PrintWriter out = resp.getWriter();
      resp.setContentType("text/html");
      RequestImpl cmr = (RequestImpl)r;
      out.println("<html>\n" +
                  "<head><title>Join Community Servlet</title></head>\n" +
                  "<body><h1>Published JOIN community request</h1>\n" +
                  "<br> <b>Agent:</b> " + getAgentIdentifier() + 
                  "<br> <b>Entity:</b> " + cmr.getEntity().getName() +
                  "<br> <b>Community:</b> " + cmr.getCommunityName() + 
                  "<br> <b>Request:</b> " + cmr + "\n" + 
                  "</body></html>\n");
      out.close();
    }
}
