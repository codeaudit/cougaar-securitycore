/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 

package org.cougaar.core.security.test;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;

import java.util.Collection;
import java.util.Iterator;
import java.util.Random;
import java.util.Vector;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.agent.service.MessageSwitchService;
import org.cougaar.core.blackboard.Directive;
import org.cougaar.core.blackboard.DirectiveMessage;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageHandler;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ServletService;
import org.cougaar.planning.ldm.PlanningDomain;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.util.UnaryPredicate;


/**
 * This plugin tests the use of Message Access Control binder.
 */
public class TestMsgAccessServletPlugin 
  extends ComponentPlugin
  implements Serializable
{
  private static Random _r  = new Random();

  private LoggingService       _log;
  private MessageSwitchService _mss;
  private PlanningFactory      _pf;

  private MessageAddress       _myAgent = null;

  private Task                 _received = null;
  private UnaryPredicate _isTask
    = new UnaryPredicate() {
        public boolean execute(Object o) 
        {
          return o instanceof Task;
        }
      };
  private IncrementalSubscription  _taskSubscription;



  private String _sendServletName    = "/message/sendVerb";
  private String _receiveServletName = "/message/receiveVerb";

  protected void setupSubscriptions() 
  {
    ServiceBroker sb = getServiceBroker();
    _log =  (LoggingService)sb.getService(this, LoggingService.class, null);
    
    _taskSubscription = 
      (IncrementalSubscription) blackboard.subscribe(_isTask);
    AgentIdentificationService ais = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null); 
    _myAgent = ais.getMessageAddress();

    _mss = (MessageSwitchService)
      sb.getService(this, MessageSwitchService.class, null);

    //get input
    DomainService ds 
      = (DomainService) sb.getService(this, DomainService.class, null);
    _log.debug("ds = " + ds + " ds class = " + ds.getClass().getName());
    _pf = (PlanningFactory) ds.getFactory(PlanningDomain.class);
    _log.debug("pf = " + _pf);

    ServletService servletService
      = (ServletService) sb.getService(this, ServletService.class, null);
    try {
      servletService.register(_sendServletName, new SendServlet());
      servletService.register(_receiveServletName, new ReceiveServlet());
    } catch ( Exception e ) {
      _log.error("Could not register servlets for testing sending directives", 
                e);
    }
    
  }

  protected void execute() 
  {
    for (Iterator tIt 
           = _taskSubscription.getAddedCollection().iterator();
         tIt.hasNext();) {
      _received = (Task) tIt.next();
    }
  }


  private class SendServlet extends HttpServlet 
  {
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
                  _sendServletName + 
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

          Verb verb = Verb.get(theVerb);
          _log.debug("pf = " + _pf);
          NewTask task = _pf.newTask();
          task.setVerb(verb);
          //create the message
          Directive[] d = new Directive[1];
          d[0] = task;
          DirectiveMessage dm = new DirectiveMessage(d);
          dm.setSource(_myAgent);
          dm.setDestination(MessageAddress.getMessageAddress(theTarget));
          _mss.sendMessage(dm);

          out.println("<p>Sent directive (id = " + 
                      ") to " + theTarget + 
                      " with verb " + theVerb);
          out.println("</body>");
        }
      }
    }
  }

  private class ReceiveServlet extends HttpServlet 
  {
    protected void doGet(HttpServletRequest req,
                         HttpServletResponse resp)
      throws IOException
    {
      PrintWriter out = resp.getWriter();
      out.print("<html>\n" + 
                "<head>\n" + 
                "<TITLE>Message Receiving Servlet</TITLE>\n" + 
                "</head>\n" + 
                "<body>\n");
      if (_received == null) {
        out.print("No tasks received");
      } else {
        out.print("Task received with verb " + _received.getVerb());
      }
      out.print("</body>");
    }
  }

}
