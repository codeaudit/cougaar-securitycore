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
import org.cougaar.core.servlet.ComponentServlet;
import org.cougaar.util.ConfigFinder;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Writer;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides a Servlet whose only job is to read a config file and
 * display the data.
 */
public class RunCodeServlet extends ComponentServlet {
  String _path = "/runCode";

  protected String getPath() {
    return _path;
  }
  
  public void setParameter(Object o) {
    if (o == null) {
      return;
    }
    
    List l = (List) o;
    if (l.isEmpty()) {
      return;
    }
    
    _path = l.get(0).toString();
  }

  public void service(HttpServletRequest req, HttpServletResponse resp) 
    throws IOException {
    String clz = req.getParameter("class");
    if (clz == null) {
      sendForm(resp);
    } else {
      runCode(clz, resp);
    }
  }
  
  public void sendForm(HttpServletResponse resp) throws IOException {
    PrintWriter out = resp.getWriter();
    resp.setContentType("text/html");
    out.println("<html>\n" +
                "<head><title>Execute Code</title></head>\n" +
                "<body><h1>Execute Code</h1>\n" +
                "<form action=\"\">\n" +
                "Class name: <input type=\"text\" name=\"class\" " +
                "value=\"\">\n" +
                "<input type=\"submit\"></form></body></html>\n");
    out.close();
  }

  public void runCode(String className, HttpServletResponse resp) 
    throws IOException {
    resp.setContentType("text/html");
    PrintWriter out = resp.getWriter();
    try {
      Class c = Class.forName(className);
      Object o = null;
      boolean written = false;
      try {
        Constructor ctr = c.getConstructor(new Class[] {PrintWriter.class});
        o = ctr.newInstance(new Object[] {out});
        written = true;
      } catch (NoSuchMethodException e) {
        // use default constructor
        o = c.newInstance();
      }
      if (Runnable.class.isAssignableFrom(c)) {
        ((Runnable)o).run();
      }
      if (!written) {
        out.print("<html><head><title>" +
                  className + "</title></head><body>\n" +
                  "<h1>Success!</h1></body></html>\n");
      }
    } catch (Exception e) {
      out.print("<html><head><title>" + className +
                "</title></head>\n" +
                "<body><h1>Failure!</h1>\n" +
                "<pre>\n");
      e.printStackTrace(out);
      out.print("\n</pre>\n</body></html>\n");
    }
    out.close();
  }
}
