/*
 * <copyright>
 *  Copyright 2000-2001 BBNT Solutions, LLC
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

import java.io.*;

import javax.servlet.*;
import javax.servlet.http.*;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.component.*;
import org.cougaar.core.service.*;
import org.cougaar.core.servlet.BaseServletComponent;

import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.core.blackboard.Directive;
import org.cougaar.core.blackboard.DirectiveMessage;
import org.cougaar.core.mts.*;

public class AddTaskServlet 
extends BaseServletComponent 
{

  private MessageAddress agentId;
//  private BlackboardService blackboard;
  private DomainService ds;
  private AgentIdentificationService ais;
  private PlanningFactory planningFactory;

  public void load() {
    if(agentId == null) {
      ais = (AgentIdentificationService)
        serviceBroker.getService(this, AgentIdentificationService.class, null);
      agentId = ais.getMessageAddress();
    }
    super.load();
    initTransport();
  }

  protected String getPath() {
    return "/addtask";
  }

  //
  // These "setXService(XService x) {..}" methods
  // are equivalent to the SimpleServletComponent's
  // "public void load() { .. serviceBroker.getService(..); .. }"
  // calls, EXCEPT that:
  //   1) these methods are only called at load-time.
  //   2) if one of these services is not available then this 
  //      Component will NOT be loaded.  In contrast, the 
  //      "load()" pattern allows the Component to (optionally) 
  //      continue loading even if any "getService(..)" returns null.
  //   3) these "setXService(..)" will request the service with
  //      "this" as the requestor.  The more generic "getService(..)"
  //      API allows the Component to pass a different class
  //      (e.g. an inner class to handle callbacks).
  //

//  public void setBlackboardService(BlackboardService blackboard) {
//    this.blackboard = blackboard;
//  }
  public void setAgentIdentificationService(AgentIdentificationService ais) {
    this.ais = ais;
    agentId = ais.getMessageAddress();
  }
  public void setDomainService(DomainService ds) {
    this.ds = ds;
    this.planningFactory = (PlanningFactory)ds.getFactory(PlanningFactory.class);
  }

  protected Servlet createServlet() {
    return new MyServlet();
  }

  public void unload() {
    super.unload();
    // FIXME release the rest!
  }

  private class MyServlet extends HttpServlet {
  public void doPost (HttpServletRequest  req, HttpServletResponse res)
    throws ServletException,IOException
  {
    String caCN =(String)req.getParameter("CN");
    String caOU =(String)req.getParameter("OU");
     PrintWriter out=res.getWriter();
 
      
      // add a new task to the blackboard:
      NewTask nt = planningFactory.newTask();
      nt.setSource(agentId);
      nt.setVerb(Verb.getVerb(caOU));
  //create the message
    Directive[] d = new Directive[1];
    d[0] = nt;
    DirectiveMessage dm = new DirectiveMessage(d);
    dm.setSource(agentId);
    dm.setDestination(MessageAddress.getMessageAddress(caCN));
    mts.sendMessage(dm);

      out.println(
          "AddTaskServletComponent "+
          "publish-Added task (<tt>"+
          nt.getUID()+
          "</tt>) with verb \"<tt>"+
          nt.getVerb()+
          "</tt>\" to agent <b>"+
          caCN+
          "</b>'s Blackboard.");
      out.println("</body></html>");
    out.flush();
    out.close();
  }
  
  public void doGet(
        HttpServletRequest req,
        HttpServletResponse res) throws IOException {

    res.setContentType("text/html");
    PrintWriter out=res.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>Message Access Binder tester</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Message Access Binder Test</H2>");

    out.println("<table>");
    out.println("<form action=\"" + req.getRequestURI() + "\" method =\"post\">");

    out.println("<tr><td>");
    out.println("Target Agent:</td><td><input name=\"CN\" type=\"text\" value=\"\">");
    out.println("</td></tr>");

    out.println("<tr><td>");
    out.println("verb:</td><td><input name=\"OU\" type=\"text\" value=\"\">");
    out.println("</td></tr>");

    out.println("<br><input type=\"submit\" value=\"Send\">&nbsp;&nbsp;&nbsp;");
    //out.println("<input type=\"reset\">");
    out.println("</form></table>");

    out.println("</body></html>");
    out.flush();
    out.close();
      
    }
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
          return agentId;
        }
      };

    // get the message transport
    mts = (MessageTransportService) 
      bindingSite.getServiceBroker().getService(
	mtc,   // simulated client 
	MessageTransportService.class,
	null);
    if (mts == null) {
      System.out.println(
	"Unable to get message transport service");
    }
  }

}
