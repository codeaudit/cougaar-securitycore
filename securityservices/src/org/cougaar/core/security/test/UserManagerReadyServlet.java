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
import org.cougaar.core.security.services.acl.UserService;
import org.cougaar.core.security.services.acl.UserServiceException;
import org.cougaar.util.ConfigFinder;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Writer;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides a Servlet whose only job is to read a config file and
 * display the data.
 */
public class UserManagerReadyServlet extends ComponentServlet {
  String _path = "/userManagerReady";

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
    String userid = req.getParameter("user");
    if (userid == null) {
      userid = "mbarger";
    }
    resp.setContentType("text/xml");
    PrintWriter out = resp.getWriter();

    out.println("<?xml version='1.0' encoding='UTF-8'?>");
    out.println("<user-manager-servlet>");
    UserService userService = (UserService)
      this.serviceBroker.getService(this, UserService.class, null);
    String domain = null;
    Map user = null;
    try {
      domain = userService.getDefaultDomain();
      user   = userService.getUser(userid);
    } catch (UserServiceException e) {}
    if (domain == null) {
      domain = "";
    }
    String userName = "";
    if (user != null) {
      userName = user.get(userService.getUserIDAttribute()).toString();
    }
    out.println("  <domain>" + domain + "</domain>");
    out.println("  <user>" + userName + "</user>");
    out.println("</user-manager-servlet>");
    this.serviceBroker.releaseService(this, UserService.class, userService);
  }
  
}
