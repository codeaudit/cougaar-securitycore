/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
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
package org.cougaar.core.security.test.memory;

import org.cougaar.core.servlet.BaseServletComponent;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.CharArrayWriter;
import java.lang.ref.Reference;
import java.util.*;
import java.util.singleton.CollectionMonitorStats;
import java.util.singleton.CollectionMonitorStatsImpl;
import java.util.singleton.EntityStats;
import java.util.singleton.EntityData;
import java.security.Principal;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CollectionMonitorServlet 
extends BaseServletComponent 
{

//  private BlackboardService blackboard;

  private CollectionMonitorStats _stats;
  private EntityStats _entityStats;

  // Values of servlet parameters
  private static final String REQ_TYPE_AGENT = "agent";
  private static final String REQ_TYPE_COMPONENT = "component";
  private static final String REQ_TYPE_GLOBAL = "global";

  // Names of servlet parameters
  private static final String REQ_GET_REQUEST_TYPE = "req";
  private static final String REQ_ROWS = "Rows";
  private static final String REQ_LINES = "Lines";
  private static final String REQ_AGENT_NAME = "agent";
  private static final String REQ_COMPONENT_NAME = "component";
  private static final String REQ_COLLECTION = "collection";

  public void load() {
    super.load();
    _stats = CollectionMonitorStatsImpl.getInstance();
    _entityStats = _stats.getEntityStats();
  }

  protected String getPath() {
    return "/collectionMonitor";
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
      throws ServletException,IOException {
      String type =(String)req.getParameter(REQ_COLLECTION);
      int rows = Integer.parseInt(req.getParameter(REQ_ROWS));
      int lines = Integer.parseInt(req.getParameter(REQ_LINES));

      res.setContentType("text/html");
      PrintWriter out=res.getWriter();
      try {
	out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
	out.println("<html>");
	out.println("<head>");
	out.println("<title>Collection Monitor Stats</title>");
	out.println("</head>");
	out.println("<body>");
	out.println("<H2>Collection Monitor Stats</H2>");
      
	out.println("<table align=\"center\" border=\"2\">");
	
	printElementsStats(out, rows, lines, type);

	out.println("</table>");
	out.println("</body></html>");
      }
      catch (Exception e) {
	out.println("Error: " + e.toString());
	e.printStackTrace(out);
      }

      out.flush();
      out.close();
    }

    private void printAgentStats(PrintWriter out,
				 HttpServletRequest req)
      throws IOException {
      out.println("<table border=\"2\">");      
      out.println("<form action=\"" + req.getRequestURI() + "\" method =\"post\">");

      out.println("<tr>");
      out.println("<th><b>Agent</th>");
      out.println("<th><b>Type</th>");
      out.println("<th><b>Current Allocations</th>");
      out.println("<th><b>Total Allocations</th>");
      out.println("<th><b>Garbage Collected</th>");
      out.println("<th><b>Total elements</th>");
      out.println("<th><b>Mean size</th>");
      out.println("<th><b>Median size</th>");
      out.println("</tr>");

      EntityStats.CollectionBinding collections[] =
	_entityStats.getCollections();

      for (int i = 0 ; i < collections.length ; i++) {
	Class cl = collections[i].getType();
	EntityStats es = collections[i].getEntityStats();

	Map map = es.getAgentStats();
	Iterator it = map.entrySet().iterator();
	while (it.hasNext()) {
	  Map.Entry m = (Map.Entry) it.next();
	  String agentName = (String) m.getKey();
	  EntityStats.Stats st = (EntityStats.Stats) m.getValue();

	  out.println("<tr>");
	  out.print("<td>");

	  out.println("<a href=\"" + req.getRequestURI()
		      + "?" + REQ_GET_REQUEST_TYPE + "=" + REQ_TYPE_AGENT
		      + "&" + REQ_AGENT_NAME + "=" + agentName
		      + "\">" + agentName + "</a>");

	  out.print("</td>");
	  // Radio button with name
	  out.println("<td>" + es.getShortName() + "</td>");
	  
	  // Currently allocated collections
	  out.println("<td>" + st._currentAllocations + "</td>");
	  // Total allocations
	  out.println("<td>" + st._totalAllocations + "</td>");
	  // Garbage collected
	  out.println("<td>" + st._garbageCollected + "</td>");
	  out.println("<td>" + st._totalNumberOfElements + "</td>");
	  out.println("<td>" + "0"   + "</td>");
	  out.println("<td>" + "0"
		      + "</td>");
	  out.print("</tr>");
	}
	out.flush();
      }

      printRequestParameters(out);

      out.println("</form>");
      out.println("</table>");
    }

    private double getMean(EntityStats es) {
      double mean = ((double)(es.getTotalNumberOfElements(false)) /
		     (double)(es.getCurrentAllocations(false))) * 100;
      mean = ((double)Math.round(mean) ) / 100;
      return mean;
    }

    private double getMedian(EntityStats es) {
      double median = es.getMedianSize(true);
      median = ((double)Math.round(median) ) / 100;
      return median;
    }

    private void printComponentStats(PrintWriter out,
				     HttpServletRequest req)
      throws IOException {
      out.println("<table border=\"2\">");      
      out.println("<form action=\"" + req.getRequestURI() + "\" method =\"post\">");

      out.println("<tr>");
      out.println("<th><b>Component</th>");
      out.println("<th><b>Type</th>");
      out.println("<th><b>Current Allocations</th>");
      out.println("<th><b>Total Allocations</th>");
      out.println("<th><b>Garbage Collected</th>");
      out.println("<th><b>Total elements</th>");
      out.println("<th><b>Mean size</th>");
      out.println("<th><b>Median size</th>");
      out.println("</tr>");

      out.println("<tr><td><input type=\"submit\" value=\"Submit\"/></td></tr>");
      out.println("</form>");
      out.println("</table>");
    }

    private void printGlobalStats(PrintWriter out,
				  HttpServletRequest req)
      throws IOException {
      out.println("<table border=\"2\">");      
      out.println("<form action=\"" + req.getRequestURI() + "\" method =\"post\">");

      EntityStats.CollectionBinding collections[] =
	_entityStats.getCollections();
      out.println("<tr><th><b>Type</th>");
      out.println("<th><b>Current Allocations</th>");
      out.println("<th><b>Total Allocations</th>");
      out.println("<th><b>Garbage Collected</th>");
      out.println("<th><b>Total elements</th>");
      out.println("<th><b>Mean size</th>");
      out.println("<th><b>Median size</th>");
      out.println("</tr>");
      for (int i = 0 ; i < collections.length ; i++) {
	Class cl = collections[i].getType();
	EntityStats es = collections[i].getEntityStats();
	out.println("<tr><td>");
	// Radio button with name
	out.println(
	  "<input type=\"radio\" name=\"" + REQ_COLLECTION + "\" "
	  + "value=\"" + cl.getName() + "\"/>"
	  + es.getShortName() + "</td>");
	// Currently allocated collections
	out.println("<td>" +
		    es.getCurrentAllocations(true) + "</td>");
	// Total allocations
	out.println("<td>" +
		    es.getTotalAllocations(false) + "</td>");
	// Garbage collected
	out.println("<td>" +
		    es.getGarbageCollected(false) + "</td>");
	out.println("<td>" +
		    es.getTotalNumberOfElements(false) + "</td>");
	out.println("<td>" + getMean(es)
		    + "</td>");
	out.println("<td>" + getMedian(es)
		    + "</td>");
	out.print("</tr>");
	out.flush();
      }
      printRequestParameters(out);

      out.println("</form>");
      out.println("</table>");
    }

    private void printRequestParameters(PrintWriter out) {
      out.println("<tr><td><i>Number of rows:");
      out.println("</td><td><input name=\"" + REQ_ROWS +
		  "\" type=\"text\" value=\"20\"><br/>");
      out.println("</td></tr>");

      out.println("<tr><td><i>Number of lines in stack trace:");
      out.println("</td><td><input name=\"" + REQ_LINES +
		  "\" type=\"text\" value=\"3\"><br/>");
      out.println("</td></tr>");
      out.println("<tr><td><input type=\"submit\" value=\"Submit\"/></td></tr>");
    }

    public void doGet(HttpServletRequest req,
		      HttpServletResponse res) throws IOException {
      String requestType =(String)req.getParameter(REQ_GET_REQUEST_TYPE);

      res.setContentType("text/html");
      PrintWriter out=res.getWriter();
      try {
	out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
	out.println("<html>");
	out.println("<head>");
	out.println("<title>Collection Monitor Stats</title>");
	out.println("</head>");
	out.println("<body>");

	out.println("<li><a href=\"" + req.getRequestURI()
		    + "?" + REQ_GET_REQUEST_TYPE + "=" + REQ_TYPE_GLOBAL
		    + "\">Global stats</a></li>");

	out.println("<li><a href=\"" + req.getRequestURI()
		    + "?" + REQ_GET_REQUEST_TYPE + "=" + REQ_TYPE_AGENT
		    + "\">Stats per agent</a></li>");

	out.println("<li><a href=\"" + req.getRequestURI()
		    + "?" + REQ_GET_REQUEST_TYPE + "="
		    + REQ_TYPE_COMPONENT
		    + "\">Stats per component</a></li><br/><br/>");

	if (requestType != null &&
	    requestType.equals(REQ_TYPE_AGENT)) {
	  printAgentStats(out, req);
	}
	else if (requestType != null &&
		 requestType.equals(REQ_TYPE_COMPONENT)) {
	    printComponentStats(out, req);
	}
	else {
	  printGlobalStats(out, req);
	}

	out.println("</body></html>");
      }
      catch (Exception e) {
	out.println("Error: " + e);
	e.printStackTrace(out);
      }
      out.flush();
      out.close();
    }

    public void printElementsStats(PrintWriter out, int rows,
				   int lines, String type) {

      EntityStats es = _entityStats.getEntityStats(type);
      int n = es.getCurrentAllocations(true);
      out.println("Number of " + es.getShortName()
		  + ":" + n + "<br/>");
      List l = es.getTopCollections(Math.min(n, rows));

      out.println("<tr><th>Stack Trace</th>");
      out.println("<th>Current Size</th>");
      out.println("<th>Max Size</th>");
      out.println("<th>Principals</th>");
      out.println("</tr>");

      if (l != null) {
	Iterator it = l.iterator();
	while (it.hasNext()) {
	  Map.Entry s = (Map.Entry) it.next();
	  Object o = ((Reference)s.getKey()).get();
	  EntityData ed = (EntityData) s.getValue();
	  out.println("<tr><td>");
	  StackTraceElement ste[] = ed.getThrowable().getStackTrace();
	  /* Skip the first two frames which are not very interesting:
	   *   CollectionMonitorStatsImpl.addHashtable()
	   *   MemoryTracker.add()
	   */
	  int LINES_TO_SKIP = 3;
	  
	  for (int i = LINES_TO_SKIP ;
	       i < Math.min(ste.length, lines + LINES_TO_SKIP) ; i++) {
	    out.println("<font size=\"2\">");
	    out.print(ste[i].getClassName() + "." +
		      ste[i].getMethodName() + "(" +
		      ste[i].getFileName() + ":" +
		      ste[i].getLineNumber() + ")");
	    if (i == LINES_TO_SKIP) {
	      out.print("<b>" + Integer.toHexString(o.hashCode()) + "</b>");
	    }
	    out.print("<br/>");
	  }
	  out.println("</td>");
	  out.println("<td>" + ed.getCurrentSize(true) + "</td>");
	  out.println("<td>" + ed.getMaxSize(false) + "</td>");

	  out.println("<td>");
	  out.println("<font size=\"2\">");
	  /*
	  Set set = ed.getPrincipals();
	  if (set != null) {
	    Iterator it2 = set.iterator();
	    while (it2.hasNext()) {
	      Principal p = (Principal) it2.next();
	      out.println(p);
	      out.println(" [" + p.getClass().getName() + "]<br/>");
	    }
	  }
	  */
	  String agent = ed.getAgentName();
	  if (agent == null) {
	    agent = "";
	  }
	  String component = ed.getComponentName();
	  if (component == null) {
	    component = "";
	  }
	  out.println("Agent: <b>" + agent + "</b><br/>");
	  out.println("Component: <b>" + component + "</b><br/>");
	  out.println("</td>");

	  out.println("</tr>");
	}
      }
    }
  }
}
