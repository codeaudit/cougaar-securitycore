/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package org.cougaar.core.security.monitoring.servlet;

// Imported java classes
import java.io.*;
import java.util.Collection;
import java.util.Iterator;
import javax.servlet.*;
import javax.servlet.http.*;

// IDMEF
import edu.jhuapl.idmef.*;

// Cougaar core services
import org.cougaar.core.servlet.SimpleServletSupport;
import org.cougaar.util.*;

// Cougaar security services
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;

/**
 *  Use the TraX interface to perform a transformation.
 */
public class EventViewerServlet
  extends HttpServlet
{
  private SimpleServletSupport support;
  private ConfigFinder confFinder;

   /** Creates new predicate to search for Events */
  class IdmefEventPredicate implements UnaryPredicate
  {
    /** @return true if the object "passes" the predicate */
    public boolean execute(Object o) {
      if (o instanceof Event)  {
	Event event= (Event)o;
	IDMEF_Message msg = event.getEvent();
	return true;
      }
      return false;
    }
  }

  public EventViewerServlet(SimpleServletSupport support) {
    this.support = support;

    confFinder = new ConfigFinder();
  }

  public void init(ServletConfig config)
    throws ServletException {
  }

  public void doGet(HttpServletRequest request,
		    HttpServletResponse response)
    throws IOException {
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>IDMEF Events</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>IDMEF Events</H2><BR>");

    // Query the blackboard
    Collection collection = support.queryBlackboard(new IdmefEventPredicate());
    Iterator it = collection.iterator();
    String document = null;

    out.print("<table border=\"1\" cellpadding=\"10\">");
    out.print("<tr>");
    out.print("<td><b><i>Alert ID</i></b></td>");
    out.print("<td><b><i>Create Time</i></b></td>");
    out.print("<td><b><i>Classification</i></b></td>");
    out.print("<td><b><i>Assessment</i></b></td>");
    out.print("<td><b><i>Analyzer</i></b></td>");
    out.print("<td><b><i>Source</i></b></td>");
    out.print("<td><b><i>Target</i></b></td>");
    out.print("<td><b><i>Additional Data</i></b></td>");
    out.print("</tr>");

    if (!it.hasNext()) {
      out.print("No Event available");
    }

    while (it.hasNext()) {
      IDMEF_Message msg = ((Event)it.next()).getEvent();
      document = msg.toString();
      System.out.println("IDMEF message:\n" + document);
      processMessage(out, msg);
    }
    out.println("</body></html>");
    out.flush();
    out.close();
  }

  private void processMessage(PrintWriter out, IDMEF_Message msg) {
    out.print("<tr>");
    String value = null;

    if (msg instanceof Alert) {
      // Alert
      Alert alert = (Alert) msg;
      // Identifier
      out.print("<td>" + alert.getIdent() + "</td>");

      // Creation Time
      CreateTime createTime = alert.getCreateTime();
      value = (createTime != null) ? createTime.getidmefDate() : "";
      out.print("<td>" + value + "</td>");

      // Classification
      Classification[] classifications = alert.getClassifications();
      out.print("<td>");
      if (classifications != null) {
	for (int i = 0 ; i < classifications.length ; i++) {
	  out.print("[" + i + "] Origin:" + classifications[i].getOrigin() + "<br>");
	  out.print("   Name:" + classifications[i].getName() + "<br>");
	}
      }
      out.print("</td>");

      // Assessment
      Assessment assessement = alert.getAssessment();
      value = (assessement != null) ? assessement.toString() : "";
      out.print("<td>" + value + "</td>");

      // Analyzer
      Analyzer analyzer = alert.getAnalyzer();
      out.print("<td>");
      if (analyzer != null) {
	out.print("Analyzer ID:" + analyzer.getAnalyzerid() + "<br>");
      }
      out.print("</td>");

      // Sources
      out.print("<td>");
      Source[] sources = alert.getSources();
      if ( sources!= null) {
	for (int i = 0 ; i < sources.length ; i++) {
	  out.print("[" + i + "]");
	  IDMEF_Node n = sources[i].getNode();
	  printNode(out, n);
	  out.print("<br>");
	}
      }
      out.print("</td>");

      // Targets
      out.print("<td>");
      Target[] targets = alert.getTargets();
       if (targets != null) {
	for (int i = 0 ; i < targets.length ; i++) {
	  out.print("[" + i + "]");
	  IDMEF_Node n = targets[i].getNode();
	  printNode(out, n);
	  out.print("<br>");
	}
      }
     out.print("</td>");

      // Additional Data
      out.print("<td>");
      AdditionalData[] additionalData = alert.getAdditionalData();
      value = (additionalData != null) ? additionalData.toString() : "";
      out.print("</td>");

    }
    // Heatbeat
    else if (msg instanceof Heartbeat) {
      Heartbeat heartbeat = (Heartbeat) msg;

      // Identifier
      out.print("<td>" + heartbeat.getIdent() + "</td>");

      // Creation Time
      CreateTime createTime = heartbeat.getCreateTime();
      value = (createTime != null) ? createTime.getidmefDate() : "";
      out.print("<td>" + value + "</td>");

      out.print("<td></td> <td></td>");

      // Analyzer
      Analyzer analyzer = heartbeat.getAnalyzer();
      out.print("<td>");
      if (analyzer != null) {
	out.print("Analyzer ID:" + analyzer.getAnalyzerid() + "<br>");
      }
      out.print("</td>");

      // Additional Data
      AdditionalData[] additionalData = heartbeat.getAdditionalData();
      value = (additionalData != null) ? additionalData.toString() : "";
      out.print("<td>" + value + "</td>");
    }
    else {
      out.print("Unknow Event");
    }
    out.print("</tr>");
  }

  private void printNode(PrintWriter out, IDMEF_Node n) {
    out.print("Ident:" + n.getIdent() + "<br>");
    out.print("Name:" + n.getName() + "<br>");
    out.print("Category:" + n.getCategory() + "<br>");
    out.print("Location:" + n.getLocation() + "<br>");

    Address[] addresses = n.getAddresses();
    if ( addresses != null) {
      for (int i = 0 ; i < addresses.length ; i++) {
	out.print("Address[" + i + "]/" + addresses[i].getCategory()
		  + " = " + addresses[i].getAddress());
      }
    }
  }
}
