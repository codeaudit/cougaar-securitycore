/*
 * <copyright>
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

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.blackboard.Directive;
import org.cougaar.core.blackboard.DirectiveMessage;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageTransportClient;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.MessageTransportService;
import org.cougaar.core.service.ServletService;
import org.cougaar.planning.ldm.PlanningDomain;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Verb;

import java.util.Collection;

/**
 * This plugin tests the use of Message Access Control binder.
 */
public class TestMsgAccessServletPlugin extends ComponentPlugin
{
  private LoggingService log;
  private BlackboardService bbs = null;
  private MessageAddress myAgent = null;
  private PlanningFactory pf;

  private ServletService _servletService;
  private String sendServletName = "/message/sendVerb";

  private NewTask task;

  protected void setupSubscriptions() {
    ServiceBroker sb = getServiceBroker();
    log =  (LoggingService)sb.getService(this, LoggingService.class, null);

    bbs = getBlackboardService();
    AgentIdentificationService ais = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null); 
    myAgent = ais.getMessageAddress();

    //get input
    Collection params = getParameters();
    initTransport();
    DomainService ds 
      = (DomainService) sb.getService(this, DomainService.class, null);
    log.debug("ds = " + ds + " ds class = " + ds.getClass().getName());
    pf = (PlanningFactory) ds.getFactory(PlanningDomain.class);
    log.debug("pf = " + pf);

    _servletService
      = (ServletService) sb.getService(this, ServletService.class, null);
    try {
      _servletService.register(sendServletName, new RequestServlet());
    } catch ( Exception e ) {
      log.error("Could not register servlets for testing sending directives", 
                e);
    }
    
  }

  protected void execute() {
  }

  private MessageTransportClient mtc;
  private MessageTransportService mts;
  private void initTransport() {
    // create a dummy message transport client
    mtc = new MessageTransportClient() {
        public void receiveMessage(Message message) {
	  //completeTransfer(message);
        }
        public MessageAddress getMessageAddress() {
          return myAgent;
        }
      };

    // get the message transport
    mts = (MessageTransportService) 
      getBindingSite().getServiceBroker().getService(
	mtc,   // simulated client 
	MessageTransportService.class,
	null);
    if (mts == null) {
      System.out.println(
                         "Unable to get message transport service");
    }
  }

  private class RequestServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req,
                         HttpServletResponse resp)
      throws IOException
    {
      doPost(req, resp);
    }

    protected void doPost(HttpServletRequest req, 
                          HttpServletResponse resp)
      throws IOException
    {
      PrintWriter out = resp.getWriter();
      out.print("<html>\n" + 
                "<head>\n" + 
                "<TITLE>Message Request Servlet</TITLE>\n" + 
                "</head>\n" + 
                "<body>\n");
        out.println("<form name=\"send\" action=\"" + 
                    "/$" + getAgentIdentifier().toAddress() +
                    sendServletName + 
                    "/Sending\" method=\"POST\">\n" +
                    "<br>\n" +
                    "Send a message to: " +
                    "  <input type=\"text\" name=\"address\">\n" +
                    " with verb" + 
                    "  <input type=\"text\" name=\"verb\">\n" +
                    "  <input type=\"submit\" name=\"Send\">\n" +
                    "</form>");
        if (req != null) {
          String theTarget = req.getParameter("address");
          String theVerb   = req.getParameter("verb");
          if (theTarget != null && theVerb != null) {
            out.print("<html>\n" + 
                      "<head>\n" + 
                      "<TITLE>Message Sending Servlet</TITLE>\n" + 
                      "</head>\n" + 
                      "<body>\n");

            Verb verb = Verb.getVerb(theVerb);
            log.debug("pf = " + pf);
            task = pf.newTask();
            task.setVerb(verb);
            //create the message
            Directive[] d = new Directive[1];
            d[0] = task;
            DirectiveMessage dm = new DirectiveMessage(d);
            dm.setSource(myAgent);
            dm.setDestination(MessageAddress.getMessageAddress(theTarget));
            mts.sendMessage(dm);

            out.println("<p>Sent directive to " + theTarget + 
                        " with verb " + theVerb);
            out.println("</body>");
          }
        }

    }
  }
}
