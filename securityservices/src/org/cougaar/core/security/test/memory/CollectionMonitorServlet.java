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
import java.util.*;
import java.util.singleton.CollectionMonitorStats;
import java.util.singleton.CollectionMonitorStatsImpl;
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
  private CollectionUtil _util;

  public void load() {
    super.load();
    _stats = CollectionMonitorStatsImpl.getInstance();
    _util = CollectionUtil.getInstance();
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
      String type =(String)req.getParameter("collection");
      int rows = Integer.parseInt(req.getParameter("Rows"));
      int lines = Integer.parseInt(req.getParameter("Lines"));

      res.setContentType("text/html");
      PrintWriter out=res.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println("<title>Collection Monitor Stats</title>");
      out.println("</head>");
      out.println("<body>");
      out.println("<H2>Collection Monitor Stats</H2>");
      
      out.println("<table align=\"center\" border=\"2\">");
      
      if (type.equals("Hashtable")) {
	printElementsStats(out, rows, lines, CollectionUtil.HASH_TABLE);
      }
      else if (type.equals("HashSet")) {
	printElementsStats(out, rows, lines, CollectionUtil.HASH_SET);
      }
      else if (type.equals("HashMap")) {
	printElementsStats(out, rows, lines, CollectionUtil.HASH_MAP);
      }
      else if (type.equals("ArrayList")) {
	printElementsStats(out, rows, lines, CollectionUtil.ARRAY_LIST);
      }
      else if (type.equals("IdentityHashMap")) {
	printElementsStats(out, rows, lines, CollectionUtil.IDENTITY_HASH_MAP);
      }
      else if (type.equals("LinkedHashMap")) {
	printElementsStats(out, rows, lines, CollectionUtil.LINKED_HASH_MAP);
      }
      else if (type.equals("LinkedHashSet")) {
	printElementsStats(out, rows, lines, CollectionUtil.LINKED_HASH_SET);
      }
      else if (type.equals("LinkedList")) {
	printElementsStats(out, rows, lines, CollectionUtil.LINKED_LIST);
      }
      else if (type.equals("Stack")) {
	printElementsStats(out, rows, lines, CollectionUtil.STACK);
      }
      else if (type.equals("TreeMap")) {
	printElementsStats(out, rows, lines, CollectionUtil.TREE_MAP);
      }
      else if (type.equals("TreeSet")) {
	printElementsStats(out, rows, lines, CollectionUtil.TREE_SET);
      }
      else if (type.equals("Vector")) {
	printElementsStats(out, rows, lines, CollectionUtil.VECTOR);
      }
      else if (type.equals("WeakHashMap")) {
	printElementsStats(out, rows, lines, CollectionUtil.WEAK_HASH_MAP);
      }
      else {
	out.println(type + " Not implemented yet");
      }
      out.println("</table>");
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
      out.println("<title>Collection Monitor Stats</title>");
      out.println("</head>");
      out.println("<body>");
      out.println("<H2>Collection Monitor Stats</H2>");
      out.println("<table border=\"2\">");      
      out.println("<form action=\"" + req.getRequestURI() + "\" method =\"post\">");

      out.println("<tr><td>");
      out.println(
	"<input type=\"radio\" name=\"collection\" value=\"Hashtable\"/>Hashtable<br/>" +
	"<input type=\"radio\" name=\"collection\" value=\"HashSet\"/>HashSet<br/>" +
	"<input type=\"radio\" name=\"collection\" value=\"HashMap\"/>HashMap<br/>" +
      "<input type=\"radio\" name=\"collection\" value=\"ArrayList\"/>ArrayList<br/>" +
	"<input type=\"radio\" name=\"collection\" value=\"IdentityHashMap\"/>IdentityHashMap<br/>" +
	"<input type=\"radio\" name=\"collection\" value=\"LinkedHashMap\"/>LinkedHashMap<br/>" +
	"<input type=\"radio\" name=\"collection\" value=\"LinkedHashSet\"/>LinkedHashSet<br/>" +
	"<input type=\"radio\" name=\"collection\" value=\"LinkedList\"/>LinkedList<br/>" +
	"<input type=\"radio\" name=\"collection\" value=\"Stack\"/>Stack<br/>" +
	"<input type=\"radio\" name=\"collection\" value=\"TreeMap\"/>TreeMap<br/>" +
	"<input type=\"radio\" name=\"collection\" value=\"TreeSet\"/>TreeSet<br/>" +
	"<input type=\"radio\" name=\"collection\" value=\"Vector\"/>Vector<br/>" +
	"<input type=\"radio\" name=\"collection\" value=\"WeakHashMap\"/>WeakHashMap<br/>"
	);
      out.println("</td></tr>");
      out.println("<tr><td>Number of rows:");
      out.println("</td><td><input name=\"Rows\" type=\"text\" value=\"20\"><br/>");
      out.println("</td></tr>");
      out.println("<tr><td>Number of lines in stack trace:");
      out.println("</td><td><input name=\"Lines\" type=\"text\" value=\"2\"><br/>");
      out.println("</td></tr>");
      out.println("<tr><td><input type=\"submit\" value=\"Submit\"/></td></tr>");
      out.println("</form>");
      out.println("</table>");
      out.println("</body></html>");
      out.flush();
      out.close();
      
    }

    //private CharArrayWriter _caw = new CharArrayWriter();

    public void printElementsStats(PrintWriter out, int rows,
				   int lines, int type) {
      
      /*
      for (int i = 0 ; i < 100 ;  i++) {
	Hashtable h = new Hashtable();
	for (int j = 0 ; j < i ; j++) {
	  h.put(new Integer(j), "foo" + j);
	}
	_stats.addHashtable(h);
      }
      */

      int n = _util.getNumberOfElements(type);
      out.println("Number of Elements:" + n + "<br/>");
      List l = _util.getTopElements(type, Math.min(n, rows));

      out.println("<tr><th>Stack Trace</th>");
      out.println("<th>Size</th></tr>");

      Iterator it = l.iterator();
      while (it.hasNext()) {
	Map.Entry s = (Map.Entry) it.next();
	out.println("<tr><td>");
	StackTraceElement ste[] = ((Throwable)s.getValue()).getStackTrace();
	for (int i = 0 ; i < Math.min(ste.length, lines) ; i++) {
	  out.println("<font size=\"2\">");
	  out.print(ste[i].getClassName() + "." +
		    ste[i].getMethodName() + "(" +
		    ste[i].getFileName() + ":" +
		    ste[i].getLineNumber() + ")<br/>");
	}
	/*
	_caw.reset();
	s.getThrowable().printStackTrace(new PrintWriter(_caw));
	out.println(_caw.toString().replaceAll("\n", "<br>\n"));
	*/
	out.println("</td>");
	Object o = s.getKey();
	int size = -1;
	if (o instanceof Collection) {
	  size = ((Collection)o).size();
	}
	else if (o instanceof Map) {
	  size = ((Map)o).size();
	}
	out.println("<td>" + size + "</td>");
	out.println("</tr>");
      }
    }

  }
}
