/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


/*
 * Created on April 15, 2004
 *
 *
 */
package org.cougaar.core.security.test.policy;

import org.cougaar.core.servlet.BaseServletComponent;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.List;

public class TestUserPolicyServlet extends BaseServletComponent{
 private String path;
  public void load() {
    super.load();
  }

  protected String getPath() {
    return path;
  }
  public void setParameter(Object o) {
    List l=(List)o;
    path=(String)l.get(0);
  }
  
  protected Servlet createServlet() {
    return new UserPolicyServlet();
  }

  public void unload() {
    super.unload();
    // FIXME release the rest!
  }
  
  private class UserPolicyServlet extends HttpServlet {
    
    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
      throws IOException {
         response.setContentType("text/html");
         PrintWriter out = response.getWriter();
         out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
         out.println("<html>");
         out.println("<head>");
         out.println("<title>User Role policy tester Servlet </title>");
         out.println("</head>");
         out.println("<body>");
         out.println("<H2>User Role policy tester Servlet</H2>");
         out.println("</body></html>");
         out.flush();
         out.close();
    }
    
    public void doPost(HttpServletRequest request,
                       HttpServletResponse response)
      throws IOException {
      doGet(request,response);
    }
      
  } 
}
