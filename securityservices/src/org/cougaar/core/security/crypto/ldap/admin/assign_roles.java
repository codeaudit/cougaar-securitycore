package org.cougaar.core.security.crypto.ldap.admin;

import org.cougaar.core.security.crypto.ldap.admin.UserInterface;
import javax.naming.*;
import javax.naming.directory.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;
import org.apache.jasper.runtime.*;


public class assign_roles extends HttpJspBase {


    static {
    }
    public assign_roles( ) {
    }

    private static boolean _jspx_inited = false;

    public final void _jspx_init() throws org.apache.jasper.runtime.JspException {
    }

    public void _jspService(HttpServletRequest request, HttpServletResponse  response)
        throws java.io.IOException, ServletException {

        JspFactory _jspxFactory = null;
        PageContext pageContext = null;
        HttpSession session = null;
        ServletContext application = null;
        ServletConfig config = null;
        JspWriter out = null;
        Object page = this;
        String  _value = null;
        try {

            if (_jspx_inited == false) {
                synchronized (this) {
                    if (_jspx_inited == false) {
                        _jspx_init();
                        _jspx_inited = true;
                    }
                }
            }
            _jspxFactory = JspFactory.getDefaultFactory();
            response.setContentType("text/html;charset=ISO-8859-1");
            pageContext = _jspxFactory.getPageContext(this, request, response,
            			"", true, 8192, true);

            application = pageContext.getServletContext();
            config = pageContext.getServletConfig();
            session = pageContext.getSession();
            out = pageContext.getOut();

            // HTML // begin [file="/assign_roles.jsp";from=(0,128);to=(1,0)]
                out.write("\r\n");

            // end
            // begin [file="/assign_roles.jsp";from=(1,2);to=(27,0)]
                
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
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(27,2);to=(40,0)]
                out.write("\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n<html>\r\n  <head>\r\n    <script language=\"JavaScript\">\r\n<!--\r\nfunction cancelAction() {\r\n  history.go(-1);\r\n}\r\n//-->\r\n    </script>\r\n  </head>\r\n  <body>\r\n");

            // end
            // begin [file="/assign_roles.jsp";from=(40,2);to=(45,0)]
                
                  Attributes user = (Attributes) 
                    request.getAttribute(UserInterface.USER_RESULTS);
                  
                  if (user != null) {  
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(45,2);to=(46,18)]
                out.write("\r\n    <form action=\"");

            // end
            // begin [file="/assign_roles.jsp";from=(46,21);to=(46,44)]
                out.print(request.getRequestURI());
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(46,46);to=(47,33)]
                out.write("\">\r\n      <input type=\"hidden\" name=\"");

            // end
            // begin [file="/assign_roles.jsp";from=(47,36);to=(47,54)]
                out.print(UserInterface.PAGE);
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(47,56);to=(48,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/assign_roles.jsp";from=(48,23);to=(48,54)]
                out.print(UserInterface.PAGE_ASSIGN_ROLES);
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(48,56);to=(49,33)]
                out.write("\">\r\n      <input type=\"hidden\" name=\"");

            // end
            // begin [file="/assign_roles.jsp";from=(49,36);to=(49,63)]
                out.print(UserInterface.LDAP_USER_UID);
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(49,65);to=(50,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/assign_roles.jsp";from=(50,23);to=(50,66)]
                out.print(user.get(UserInterface.LDAP_USER_UID).get());
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(50,68);to=(51,33)]
                out.write("\">\r\n      <input type=\"submit\" name=\"");

            // end
            // begin [file="/assign_roles.jsp";from=(51,36);to=(51,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(51,65);to=(52,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/assign_roles.jsp";from=(52,23);to=(52,55)]
                out.print(UserInterface.ACTION_BUTTON_ROLE);
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(52,57);to=(53,33)]
                out.write("\">\r\n      <input type=\"button\" name=\"");

            // end
            // begin [file="/assign_roles.jsp";from=(53,36);to=(53,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(53,65);to=(54,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/assign_roles.jsp";from=(54,23);to=(54,57)]
                out.print(UserInterface.ACTION_BUTTON_CANCEL);
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(54,59);to=(57,0)]
                out.write("\"\r\n             onClick=\"cancelAction()\">\r\n      <table>\r\n");

            // end
            // begin [file="/assign_roles.jsp";from=(57,2);to=(62,0)]
                
                    for (int i = 0; i < UserInterface.LDAP_SEARCH_FIELDS.length; i++) {
                      Object val = "";
                      Attribute attr = user.get(UserInterface.LDAP_SEARCH_FIELDS[i][0]);
                      if (attr != null) val = attr.get();
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(62,2);to=(64,14)]
                out.write("\r\n        <tr>\r\n          <td>");

            // end
            // begin [file="/assign_roles.jsp";from=(64,17);to=(64,55)]
                out.print(UserInterface.LDAP_SEARCH_FIELDS[i][1]);
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(64,57);to=(65,14)]
                out.write("</td>\r\n          <td>");

            // end
            // begin [file="/assign_roles.jsp";from=(65,17);to=(65,20)]
                out.print(val);
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(65,22);to=(67,0)]
                out.write("</td>\r\n        </tr>\r\n");

            // end
            // begin [file="/assign_roles.jsp";from=(67,2);to=(67,6)]
                  } 
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(67,8);to=(71,20)]
                out.write("\r\n      </table>\r\n      <br>Please select the roles for the user. In Windows, \r\n          use Ctrl-click to select multiple roles.<br>\r\n      <select name=\"");

            // end
            // begin [file="/assign_roles.jsp";from=(71,23);to=(71,42)]
                out.print(UserInterface.ROLES);
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(71,44);to=(72,0)]
                out.write("\" multiple>\r\n");

            // end
            // begin [file="/assign_roles.jsp";from=(72,2);to=(86,0)]
                
                    NamingEnumeration allRoles = (NamingEnumeration) 
                      request.getAttribute(UserInterface.ALL_ROLES);
                    NamingEnumeration userRoles = (NamingEnumeration)
                      request.getAttribute(UserInterface.ROLE_RESULTS);
                    HashSet userRoleList = new HashSet();
                    while (userRoles.hasMore()) {
                      SearchResult sr = (SearchResult) userRoles.next();
                      userRoleList.add(sr.getAttributes());
                    }
                    while (allRoles.hasMore()) {
                      SearchResult sr = (SearchResult) allRoles.next();
                      Attributes role = sr.getAttributes();
                      String selected = (userRoleList.contains(role))?"selected":"";
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(86,2);to=(87,16)]
                out.write("\r\n        <option ");

            // end
            // begin [file="/assign_roles.jsp";from=(87,19);to=(87,27)]
                out.print(selected);
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(87,29);to=(87,30)]
                out.write(">");

            // end
            // begin [file="/assign_roles.jsp";from=(87,33);to=(87,76)]
                out.print(role.get(UserInterface.LDAP_ROLE_RDN).get());
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(87,78);to=(88,0)]
                out.write("</option>\r\n");

            // end
            // begin [file="/assign_roles.jsp";from=(88,2);to=(91,0)]
                      
                    }
                  }
            // end
            // HTML // begin [file="/assign_roles.jsp";from=(91,2);to=(96,0)]
                out.write("\r\n      </select>\r\n    </form>\r\n  </body>\r\n</html>\r\n");

            // end

        } catch (Throwable t) {
            if (out != null && out.getBufferSize() != 0)
                out.clearBuffer();
            if (pageContext != null) pageContext.handlePageException(t);
        } finally {
            if (_jspxFactory != null) _jspxFactory.releasePageContext(pageContext);
        }
    }
}
