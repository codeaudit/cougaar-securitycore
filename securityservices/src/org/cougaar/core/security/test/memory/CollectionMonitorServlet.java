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
import java.io.ByteArrayOutputStream;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.util.*;
import java.util.singleton.CollectionMonitorStats;
import java.util.singleton.CollectionMonitorStatsImpl;
import java.util.singleton.EntityStats;
import java.util.singleton.EntityData;
import java.security.Principal;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.beans.XMLEncoder;

public class CollectionMonitorServlet 
extends BaseServletComponent 
{

//  private BlackboardService blackboard;

  private CollectionMonitorStats _stats;
  private EntityStats _entityStats;

  // Names of servlet parameters
  private static final String REQ_GET_REQUEST_TYPE = "req";

  // Values for REQ_GET_REQUEST_TYPE
  private static final String REQ_VIEW_OBJECT = "viewObject";
  private static final String REQ_TYPE_AGENT = "agent";
  private static final String REQ_TYPE_COMPONENT = "component";
  private static final String REQ_TYPE_GLOBAL = "global";

  // Name of other servlet parameters
  private static final String REQ_ROWS = "Rows";
  private static final String REQ_LINES = "Lines";
  private static final String REQ_AGENT_NAME = "agent";
  private static final String REQ_COMPONENT_NAME = "component";
  private static final String REQ_COLLECTION = "collection";
  private static final String REQ_OBJECT_REF = "objectMap";

  // Session attribute names
  private static final String REQ_OBJECT_MAP = "objectRef";

  private static final int DEFAULT_ROWS = 20;
  private static final int DEFAULT_LINES = 3;

  /** The time, in seconds, between client requests before the servlet
   * container will invalidate this session.
   */
  private static final int SESSION_INVALIDATION = 60 * 30;

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
      parseSessionParameters(req);

      int rows = getRows(req);
      int lines = getLines(req);

      String collectionType =(String)req.getParameter(REQ_COLLECTION);
      String agentName =(String)req.getParameter(REQ_AGENT_NAME);
      String componentName =(String)req.getParameter(REQ_COMPONENT_NAME);
      int queryType = EntityStats.QUERY_ALL;

      if (agentName != null) {
	queryType = EntityStats.QUERY_AGENT;
	if (agentName.equals("null")) {
	  agentName = null;
	}
      }
      if (componentName != null) {
      }

      res.setContentType("text/html");
      PrintWriter out=res.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println("<title>Collection Monitor Stats</title>");
      out.println("</head>");
      out.println("<body>");

      printHeading(out, req);

      if (collectionType == null) {
	printGlobalStats(out, req);
      }
      else {
	printDetailedStats(out, rows, lines, collectionType,
			   queryType, agentName, req);
      }
      out.println("</body></html>");
      out.flush();
      out.close();
    }

    private void parseSessionParameters(HttpServletRequest req) {
      // Parse session parameters
      HttpSession hsession = req.getSession(true);
      hsession.setMaxInactiveInterval(SESSION_INVALIDATION);
      if (req.getParameter(REQ_ROWS) != null) {
	hsession.setAttribute(REQ_ROWS, req.getParameter(REQ_ROWS));
      }
      if (req.getParameter(REQ_LINES) != null) {
	hsession.setAttribute(REQ_LINES, req.getParameter(REQ_LINES));
      }
    }

    private void printDetailedStats(PrintWriter out,
				    int rows, int lines,
				    String collectionType,
				    int queryType, String agentName,
				    HttpServletRequest req) {
      try {
	out.println("<table align=\"center\" border=\"2\">");

	printElementsStats(out, rows, lines, collectionType,
			   queryType, agentName, req);
	out.println("</table>");

      }
      catch (Exception e) {
	out.println("Error: " + e.toString());
	e.printStackTrace(out);
      }
    }

    private int getRows(HttpServletRequest req) {
      int rows = DEFAULT_ROWS;
      HttpSession hsession = req.getSession();
      if (hsession != null) {
	String s = (String)hsession.getAttribute(REQ_ROWS);
	if (s != null) {
	  rows = Integer.parseInt(s);
	}
	else {
	  rows = DEFAULT_ROWS;
	}
      }
      return rows;
    }

    private int getLines(HttpServletRequest req) {
      int lines = DEFAULT_LINES;
      HttpSession hsession = req.getSession();
      if (hsession != null) {
	String s = (String)hsession.getAttribute(REQ_LINES);
	if (s != null) {
	  lines = Integer.parseInt(s);
	}
	else {
	  lines = DEFAULT_LINES;
	}
      }
      return lines;
    }

    private void printAgentStats(PrintWriter out,
				 HttpServletRequest req,
				 String agentName,
				 String collectionType)
      throws IOException {
      if (agentName == null) {
	printAgentStats(out, req);
      }
      else {
	int rows = getRows(req);
	int lines = getLines(req);
	if (agentName.equals("null")) {
	  agentName = null;
	}
	printDetailedStats(out, rows, lines, collectionType,
			   EntityStats.QUERY_AGENT, agentName, req);
      }
    }

    private void printAgentStats(PrintWriter out,
				 HttpServletRequest req)
      throws IOException {
      out.println("<table border=\"2\">");      

      out.println("<tr>");
      out.println("<th><b>Type</th>");
      out.println("<th><b>Agent</th>");
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
	  // Name of collection
	  out.println("<td>" + es.getShortName() + "</td>");

	  out.print("<td>");
	  out.println("<a href=\"" + req.getRequestURI()
		      + "?" + REQ_GET_REQUEST_TYPE + "=" + REQ_TYPE_AGENT
		      + "&" + REQ_AGENT_NAME + "=" + agentName
		      + "&" + REQ_COLLECTION + "=" + es.getType().getName()
		      + "\">" + agentName + "</a>");

	  out.print("</td>");
	  
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
	out.print(
	  "<input type=\"radio\" name=\"" + REQ_COLLECTION + "\" "
	  + "value=\"" + cl.getName() + "\"");
	if (i == 0) {
	  // By default, first one is checked.
	  out.print(" CHECKED");
	}
	out.println("/>" + es.getShortName() + "</td>");
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
      out.println("<tr><td><input type=\"submit\" value=\"Submit\"/></td></tr>");

      out.println("</form>");
      out.println("</table>");
    }

    private void printRequestParameters(PrintWriter out,
					HttpServletRequest  req) {
      int rows = getRows(req);
      int lines = getLines(req);
      out.print("<table>");
      out.println("<tr><td><i>Number of rows:");
      out.print("</td><td><input name=\"" + REQ_ROWS +
		"\" type=\"text\" value=\"");
      out.print(rows);
      out.print("\"><br/>");
      out.println("</td></tr>");

      out.println("<tr><td><i>Number of lines in stack trace:");
      out.println("</td><td><input name=\"" + REQ_LINES +
		  "\" type=\"text\" value=\"");
      out.print(lines);
      out.print("\"><br/>");
      out.println("</td>");
      out.println("<td><input type=\"submit\" value=\"Submit\"/></td></tr>");
      out.print("</table>");
    }

    private void printHeading(PrintWriter out, HttpServletRequest req) {
      out.println("<table border=\"1\">");
      out.println("<form action=\"" + req.getRequestURI() + "\" method =\"post\">");
      out.print("<tr>");
      out.println("<td>");
      out.println("<li><a href=\"" + req.getRequestURI()
		  + "?" + REQ_GET_REQUEST_TYPE + "=" + REQ_TYPE_GLOBAL
		  + "\">Global stats</a></li>");
      
      out.println("<li><a href=\"" + req.getRequestURI()
		  + "?" + REQ_GET_REQUEST_TYPE + "=" + REQ_TYPE_AGENT
		  + "\">Stats per agent</a></li>");
      
      out.println("<li><a href=\"" + req.getRequestURI()
		  + "?" + REQ_GET_REQUEST_TYPE + "="
		  + REQ_TYPE_COMPONENT
		  + "\">Stats per component</a></li>");
      out.println("</td><td>");
      printRequestParameters(out, req);
      out.println("</td></tr>");
      out.println("</form>");
      out.println("</table><br/>");
    }

    public void doGet(HttpServletRequest req,
		      HttpServletResponse res) throws IOException {
      String requestType = (String)req.getParameter(REQ_GET_REQUEST_TYPE);
      String collectionType =
	(String)req.getParameter(REQ_COLLECTION);
      String agentName =(String)req.getParameter(REQ_AGENT_NAME);

      res.setContentType("text/html");
      PrintWriter out=res.getWriter();
      try {
	out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
	out.println("<html>");
	out.println("<head>");
	out.println("<title>Collection Monitor Stats</title>");
	out.println("</head>");
	out.println("<body>");

	printHeading(out, req);

	if (requestType != null &&
	    requestType.equals(REQ_TYPE_AGENT)) {
	  printAgentStats(out, req, agentName, collectionType);
	}
	else if (requestType != null &&
		 requestType.equals(REQ_TYPE_COMPONENT)) {
	  printComponentStats(out, req);
	}
	else if (requestType != null &&
		 requestType.equals(REQ_VIEW_OBJECT)) {
	  displayObjectContent(out, req);
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

    public void displayObjectContent(PrintWriter out,
				     HttpServletRequest req) {
      HttpSession hsession = req.getSession();
      if (hsession == null) {
	out.println("Error: cannot find HttpSession");
	return;
      }
      Map objectreferences = (Map) hsession.getAttribute(REQ_OBJECT_MAP);
      if (objectreferences == null) {
	out.println("Error: cannot find Map of object references");
	return;
      }
      String objectHash = req.getParameter(REQ_OBJECT_REF);
      if (objectHash == null) {
	out.println("Error: should provide object hash");
	return;
      }
      Reference o = (WeakReference) objectreferences.get(objectHash);
      if (o != null) {
	Object referent = o.get();
	if (referent == null) {
	  out.println("Object has been reclaimed");
	  return;
	}
	out.println("Object " +
		    Integer.toHexString(referent.hashCode())
		    + " - Class: " + referent.getClass().getName()
		    + "<br/>");
	/*
	ByteArrayOutputStream bos = new ByteArrayOutputStream();
	XMLEncoder encoder = new XMLEncoder(bos);
	encoder.writeObject(referent);
	encoder.close();
	try {
	  out.println(bos.toString("UTF-8") + "<br/>");
	}
	catch (java.io.UnsupportedEncodingException ex) {
	  out.println("Unsupported encoding<br/>");
	}
	try {
	  bos.close();
	}
	catch (IOException e) {}
	*/
	String s = referent.toString();
	s.replaceAll("\n", "<br/>");

	out.println("Object.toString():<br/>" + s);
      }
      else {
 	out.println("Cannot find object with hash: " + objectHash);
      }
    }

    /**
     */
    public void printElementsStats(PrintWriter out, int rows,
				   int lines, String collectionType,
				   int queryType, String agentName,
				   HttpServletRequest req) {

      EntityStats es = _entityStats.getEntityStats(collectionType);
      List l = null;
      if (es != null) {
	l = es.getTopCollections(Math.min(es.getCurrentAllocations(true),
					  rows),
				 queryType,
				 agentName);
	out.println("Number of " + es.getShortName()
		    + ":" + l.size() + "<br/>");
      }
      out.println("<tr><th>Stack Trace</th>");
      out.println("<th>Current Size</th>");
      out.println("<th>Max Size</th>");
      out.println("<th>Principals</th>");
      out.println("</tr>");

      if (l != null) {
	HttpSession hsession = req.getSession();
	Map objectreferences = new HashMap();
	hsession.setAttribute(REQ_OBJECT_MAP, objectreferences);

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
	  int LINES_TO_SKIP = 5;
	  
	  for (int i = LINES_TO_SKIP ;
	       i < Math.min(ste.length, lines + LINES_TO_SKIP) ; i++) {
	    out.println("<font size=\"2\">");
	    out.print(ste[i].getClassName() + "." +
		      ste[i].getMethodName() + "(" +
		      ste[i].getFileName() + ":" +
		      ste[i].getLineNumber() + ")");
	    if (i == LINES_TO_SKIP) {
	      objectreferences.put(Integer.toHexString(o.hashCode()),
				   new WeakReference(o));
	      out.println("  -   <a href=\"" + req.getRequestURI()
			  + "?" + REQ_GET_REQUEST_TYPE + "=" + REQ_VIEW_OBJECT
			  + "&" + REQ_OBJECT_REF + "=" + Integer.toHexString(o.hashCode())
			  + "\"><b>" + Integer.toHexString(o.hashCode())
			  + "</b></a>");
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
