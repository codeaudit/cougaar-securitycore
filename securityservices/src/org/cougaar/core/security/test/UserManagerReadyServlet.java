/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 

package org.cougaar.core.security.test;

// java packages
import java.io.IOException;
import java.io.PrintWriter;
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.services.acl.UserService;
import org.cougaar.core.security.services.acl.UserServiceException;
import org.cougaar.core.servlet.ComponentServlet;

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
      AccessController.doPrivileged(new PrivilegedAction() {
          public Object run() {
            return serviceBroker.getService(this, UserService.class, null);
          }
        });

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
