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
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides a Servlet whose only job is to read a config file and
 * display the data.
 */
public class ConfigReaderServlet extends ComponentServlet {
  String _path = "/readconfig";

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
    ConfigFinder cf = ConfigFinder.getInstance();
    String filename = req.getParameter("file");
    if (filename == null) {
      resp.sendError(HttpServletResponse.SC_ACCEPTED,
                     "No \"file\" parameter");
      return;
    }
    File f = cf.locateFile(filename);
    if (f == null) {
      resp.sendError(HttpServletResponse.SC_GONE,
                      "Could not locate file \"" + 
                      filename + "\"");
      return;
    }

    resp.setContentType("text/plain");
    FileReader reader = new FileReader(f);
    char buf[] = new char[1000];
    int bytes;
    Writer out = resp.getWriter();
    while ((bytes = reader.read(buf)) >= 0) {
      out.write(buf,0,bytes);
    }
    out.close();
  }
}
