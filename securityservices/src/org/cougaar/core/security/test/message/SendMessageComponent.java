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
package org.cougaar.core.security.test.message;

// java packages
import java.util.*;
import java.io.*;
import java.text.*;
import javax.servlet.http.*;

// cougaar classes
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.EventService;
import org.cougaar.core.service.ServletService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;
import org.cougaar.util.UnaryPredicate;

// security services classes
import org.cougaar.core.security.util.RelayBase;

/**
 * Provides a Servlet to send a message to another agent and gives the status
 * of all messages sent, received, and replied. The component always 
 * automatically replies to every message it receives. The type of message
 * that it listens for is TestRelay, an internal class of SendMessageComponent
 * that extends from RelayBase.
 */
public class SendMessageComponent extends ComponentPlugin {
  UIDService              _uidService;
  ServletService          _servletService;
  IncrementalSubscription _relaySub;
  LoggingService          _log;
  EventService            _eventService;
  private static final DateFormat DF = 
    new SimpleDateFormat("MM/dd/yyyy hh:mm:ss a");
  private String _paths[] = { 
    "/message/list", "/message/send", "/message/delete" 
  };
  private HttpServlet _servlets[] = new HttpServlet[] {
    new ListServlet(), new SendServlet(), new DeleteServlet()
  };

  public void setParameter(Object param) {
    List l = (List) param;
    for (int i = 0; i < _paths.length && i < l.size(); i++) {
      _paths[i] = (String) l.get(i);
    }
  }

  public void setLoggingService(LoggingService l) {
    _log = l;
  }

  public void setEventService(EventService e) {
    _eventService = e;
  }

  public void setUIDService(UIDService u) {
    _uidService = u;
  }

  protected synchronized void setupSubscriptions() {
    // if rehydrating, check for unanswered relays:
    if (this.blackboard.didRehydrate()) {
      checkRelays(blackboard.query(MY_RELAYS));
    }

    // subscribe to changes in my relays
    _relaySub = (IncrementalSubscription) this.blackboard.subscribe(MY_RELAYS);
    _servletService = (ServletService)
      getServiceBroker().getService(this, ServletService.class, null);
    for (int i = 0; i < _paths.length; i++) {
      try {
        _servletService.register(_paths[i], _servlets[i]);
      } catch (Exception e) {
        _log.error("Problem registering servlet", e);
      }
    }
  }

  protected void execute() {
    if (_relaySub.hasChanged()) {
      Collection added = _relaySub.getAddedCollection();
      if (_eventService.isEventEnabled()) {
        sendEvent(added);
        sendEvent(_relaySub.getChangedCollection());
      }
      checkRelays(added);
    }
  }

  private void sendEvent(Collection c) {
    Iterator iter = c.iterator();
    while (iter.hasNext()) {
      TestRelay relay = (TestRelay) iter.next();
      String mode;
      if (relay.isTarget()) {
        if (relay.getResponse() == null) {
          mode = "Received";
        } else {
          mode = "Responded";
        }
      } else {
        if (relay.getResponse() != null) {
          mode = "ResponseReceived";
        } else {
          mode = "Sent";
        }
      }
      String target = agentId.toAddress();
      if (!relay.isTarget()) {
        target = relay.getTargets().iterator().next().toString();
      }
      _eventService.event("[STATUS] MessageTransport(" + mode + 
                          ") UID(" + relay.getUID() + 
                          ") Source(" + relay.getSource() +
                          ") Target(" + target + ')');
    }
  }

  private void removeRelay(UID uid) {
    this.blackboard.openTransaction();
    try {
      Collection c = this.blackboard.query(new FindUID(uid));
      if (!c.isEmpty()) {
        this.blackboard.publishRemove(c.iterator().next());
      }
    } finally {
      this.blackboard.closeTransaction();
    }
  }

  private Collection getRelays() {
    this.blackboard.openTransaction();
    try {
      return this.blackboard.query(MY_RELAYS);
    } finally {
      this.blackboard.closeTransaction();
    }
  }

  private void checkRelays(Collection c) {
    Iterator iter = c.iterator();
    while (iter.hasNext()) {
      TestRelay relay = (TestRelay) iter.next();
      if (relay.isTarget()) {
        // okay, I'm the target. Has this one been answered, yet?
        if (relay.getResponse() == null) {
          // we should respond!
          relay.setResponse(/*this.agentId.toAddress() + " responded " +*/
                            DF.format(new Date()));
          this.blackboard.publishChange(relay);
        }
      }
    }
  }

  private TestRelay addRelay(MessageAddress target) {
    UID uid = _uidService.nextUID();
    TestRelay relay = new TestRelay(uid, this.agentId, target);
    relay.setContent(/*this.agentId.toAddress() + " sent " +*/
                     DF.format(new Date()));
    this.blackboard.openTransaction();
    try {
      this.blackboard.publishAdd(relay);
      return relay;
    } finally {
      this.blackboard.closeTransaction();
    }
  }

  private static final UnaryPredicate MY_RELAYS = new UnaryPredicate() {
      public boolean execute(Object obj) {
        return (obj instanceof TestRelay);
      }
    };

  public static class TestRelay extends RelayBase {
    public TestRelay(UID uid, MessageAddress source, Object content) {
      super(uid, source, content);
    }

    public TestRelay(UID uid, MessageAddress source, MessageAddress target) {
      super(uid, source, target);
    }
  }

  private static class FindUID implements UnaryPredicate {
    private UID _uid;

    public FindUID(UID uid) {
      _uid = uid;
    }

    public boolean execute(Object obj) {
      if (!(obj instanceof UniqueObject)) {
        return false;
      }
      return ((UniqueObject) obj).getUID().equals(_uid);
    }
  }

  private static boolean getBoolean(HttpServletRequest req, String param,
                                    boolean def) {
    String val = req.getParameter(param);
    if (val == null) {
      return def;
    }
    return Boolean.valueOf(val).booleanValue();
  }

  private String getListPath() {
    return "/$" + this.agentId.toAddress() + _paths[0];
  }

  private String getSendPath() {
    return "/$" + this.agentId.toAddress() + _paths[1];
  }

  private String getDeletePath(UID uid) {
    return "/$" + this.agentId.toAddress() + _paths[2] +
      "?uid=" + uid;
  }
  
  private static void setHeader(PrintWriter out, String title, boolean xml) {
    if (xml) {
      out.println("<?xml version='1.0' encoding='UTF-8'?>");
      out.println("<document>");
      out.println("  <title>" + title + "</title>");
    } else {
      out.println("<html>\n" +
                  "  <head><title>" + title + "</title></head>" +
                  "  <body><h1>" + title + "</h1>");
    }
  }

  private static void setFooter(PrintWriter out, boolean xml) {
    if (xml) {
      out.println("</document>");
    } else {
      out.println("  </body>\n" +
                  "</html>");
    }
  }

  private class SendServlet extends HttpServlet {
    protected void service(HttpServletRequest req, HttpServletResponse resp) 
      throws IOException {
      PrintWriter out = resp.getWriter();
      boolean useXML = getBoolean(req, "xml", false);
      setHeader(out, "Message Sent", useXML);
      String address = req.getParameter("address");
      MessageAddress target = MessageAddress.getMessageAddress(address);
      TestRelay relay = addRelay(target);
      if (useXML) {
        out.println("  <uid>" + relay.getUID() + "</uid>");
        out.println("  <target>" + target.toAddress() + "</target>");
      } else {
        out.println("Sent message to " + target.toAddress() +
                    " with UID (" + relay.getUID() + ")<br>");
        out.println("<a href=\"" + getListPath() + "\">list relays</a>");
      }
      setFooter(out, useXML);
    }
  }

  private class DeleteServlet extends HttpServlet {
    protected void service(HttpServletRequest req, HttpServletResponse resp) 
      throws IOException {
      PrintWriter out = resp.getWriter();
      boolean useXML = getBoolean(req, "xml", false);
      String uidStr = req.getParameter("uid");
      UID uid = UID.toUID(uidStr);
      removeRelay(uid);
      setHeader(out, "Message Deleted", useXML);
      if (useXML) {
        out.println("  <uid>" + uid + "</uid>");
      } else {
        out.println("Deleted message with UID (" + uid + ")<br>");
        out.println("<a href=\"" + getListPath() + "\">list relays</a>");
      }
      setFooter(out, useXML);
    }
  }

  private class ListServlet extends HttpServlet {
    protected void service(HttpServletRequest req, HttpServletResponse resp) 
      throws IOException {
      PrintWriter out = resp.getWriter();
      boolean useXML = getBoolean(req, "xml", false);
      setHeader(out, "Messages Sent &amp; Received", useXML);

      Collection c = getRelays();
      if (useXML) {
        printXML(out, c);
      } else {
        printHTML(out, c);
      }

      setFooter(out, useXML);
    }

    private void printXML(PrintWriter out, Collection c) {
      out.println("  <messages>");
      Iterator iter = c.iterator();
      while (iter.hasNext()) {
        TestRelay relay = (TestRelay) iter.next();
        String target = agentId.toAddress();
        if (!relay.isTarget()) {
          target = relay.getTargets().iterator().next().toString();
        }
        out.println("    <message>");
        out.println("      <uid>" + relay.getUID() + "</uid>");
        out.println("      <source>" + relay.getSource() + "</source>");
        out.println("      <target>" + target + "</target>");
        out.println("      <content>" + relay.getContent() + "</content>");
        out.println("      <response>" + relay.getResponse() + "</response>");
        out.println("    </message>");
      }
      out.println("  </messages>");
    }

    private void printHTML(PrintWriter out, Collection c) {
      Iterator iter = c.iterator();

//       out.println("<table frame=\"border\" rules=\"groups\">\n" +
      out.println("<table border=\"1\">\n" +
                  "<thead>\n" +
                  "<tr>\n" +
                  "<th>UID</th><th>Source</th>" +
                  "<th>Target</th><th>Sent Contents</th>\n" +
                  "<th>Response Contents</th><th>Delete?</th>\n" +
                  "</tr>\n" +
                  "</thead>\n" +
                  "<tbody>");
      while (iter.hasNext()) {
        TestRelay relay = (TestRelay) iter.next();
        String target = "this agent";
        if (!relay.isTarget()) {
          target = relay.getTargets().iterator().next().toString();
        }
        String receivedColor = "green";
        String response = (String) relay.getResponse();
        if (response == null) {
          receivedColor = "red";
          response = "-- no response --";
        }

        out.println("<tr>\n<td>" + relay.getUID() +
                    "</td>\n<td>" + relay.getSource() +
                    "</td>\n<td>" + target +
                    "</td>\n<td>" + relay.getContent() +
                    "</td>\n<td bgcolor=\"" + receivedColor +
                    "\">" + response +
                    "</td>\n<td><a href=\"" + getDeletePath(relay.getUID()) +
                    "\">Delete</a>" +
                    "</td>\n</tr>");
      }
      out.println("</tbody></table>\n" +
                  "<form name=\"send\" action=\"" + getSendPath() +
                  "\" method=\"GET\">\n" +
                  "<br>\n" +
                  "Send a message to: " +
                  "  <input type=\"text\" name=\"address\">\n" +
                  "  <input type=\"submit\" name=\"Send\">\n" +
                  "</form>");
    }
    
  }
}
