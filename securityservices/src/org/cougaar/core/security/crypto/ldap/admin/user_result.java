package org.cougaar.core.security.crypto.ldap.admin;

import javax.naming.*;
import javax.naming.directory.*;
import java.util.*;
import java.text.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;
import org.apache.jasper.runtime.*;


public class user_result extends HttpJspBase {


    static {
    }
    public user_result( ) {
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

            // HTML // begin [file="/user_result.jsp";from=(0,82);to=(1,0)]
                out.write("\r\n");

            // end
            // begin [file="/user_result.jsp";from=(1,2);to=(27,0)]
                
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
            // HTML // begin [file="/user_result.jsp";from=(27,2);to=(40,0)]
                out.write("\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n<html>\r\n  <head>\r\n    <script language=\"JavaScript\">\r\n<!--\r\nfunction deleteCheck() {\r\n  return confirm(\"Really delete this user?\");\r\n}\r\n// -->\r\n    </script>\r\n  </head>\r\n  <body>\r\n");

            // end
            // begin [file="/user_result.jsp";from=(40,2);to=(45,0)]
                
                  Attributes user = (Attributes) 
                    request.getAttribute(UserInterface.USER_RESULTS);
                  
                  if (user != null) {  
            // end
            // HTML // begin [file="/user_result.jsp";from=(45,2);to=(46,18)]
                out.write("\r\n    <form action=\"");

            // end
            // begin [file="/user_result.jsp";from=(46,21);to=(46,44)]
                out.print(request.getRequestURI());
            // end
            // HTML // begin [file="/user_result.jsp";from=(46,46);to=(47,33)]
                out.write("\" method=\"GET\">\r\n      <input type=\"hidden\" name=\"");

            // end
            // begin [file="/user_result.jsp";from=(47,36);to=(47,54)]
                out.print(UserInterface.PAGE);
            // end
            // HTML // begin [file="/user_result.jsp";from=(47,56);to=(48,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_result.jsp";from=(48,23);to=(48,60)]
                out.print(UserInterface.PAGE_USER_RESULT_ACTION);
            // end
            // HTML // begin [file="/user_result.jsp";from=(48,62);to=(49,33)]
                out.write("\">\r\n      <input type=\"hidden\" name=\"");

            // end
            // begin [file="/user_result.jsp";from=(49,36);to=(49,63)]
                out.print(UserInterface.LDAP_USER_UID);
            // end
            // HTML // begin [file="/user_result.jsp";from=(49,65);to=(50,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_result.jsp";from=(50,23);to=(50,66)]
                out.print(user.get(UserInterface.LDAP_USER_UID).get());
            // end
            // HTML // begin [file="/user_result.jsp";from=(50,68);to=(51,33)]
                out.write("\">\r\n      <input type=\"submit\" name=\"");

            // end
            // begin [file="/user_result.jsp";from=(51,36);to=(51,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/user_result.jsp";from=(51,65);to=(52,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_result.jsp";from=(52,23);to=(52,55)]
                out.print(UserInterface.ACTION_BUTTON_EDIT);
            // end
            // HTML // begin [file="/user_result.jsp";from=(52,57);to=(53,33)]
                out.write("\">\r\n      <input type=\"submit\" name=\"");

            // end
            // begin [file="/user_result.jsp";from=(53,36);to=(53,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/user_result.jsp";from=(53,65);to=(54,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_result.jsp";from=(54,23);to=(54,55)]
                out.print(UserInterface.ACTION_BUTTON_COPY);
            // end
            // HTML // begin [file="/user_result.jsp";from=(54,57);to=(55,33)]
                out.write("\">\r\n      <input type=\"submit\" name=\"");

            // end
            // begin [file="/user_result.jsp";from=(55,36);to=(55,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/user_result.jsp";from=(55,65);to=(56,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_result.jsp";from=(56,23);to=(56,63)]
                out.print(UserInterface.ACTION_BUTTON_ASSIGN_ROLES);
            // end
            // HTML // begin [file="/user_result.jsp";from=(56,65);to=(57,33)]
                out.write("\">\r\n      <input type=\"submit\" name=\"");

            // end
            // begin [file="/user_result.jsp";from=(57,36);to=(57,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/user_result.jsp";from=(57,65);to=(58,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_result.jsp";from=(58,23);to=(58,57)]
                out.print(UserInterface.ACTION_BUTTON_DELETE);
            // end
            // HTML // begin [file="/user_result.jsp";from=(58,59);to=(61,0)]
                out.write("\"\r\n             onClick=\"return deleteCheck();\">\r\n      <table>\r\n");

            // end
            // begin [file="/user_result.jsp";from=(61,2);to=(85,0)]
                
                    for (int i = 0; i < UserInterface.LDAP_USER_FIELDS.length; i++) {
                      String title   = UserInterface.LDAP_USER_FIELDS[i][1];
                      String field   = UserInterface.LDAP_USER_FIELDS[i][0];
                      Attribute attr = user.get(field);
                      Object val     = null;
                      int size = 0;
                      if (attr != null) {
                        val = attr.get();
                        size = attr.size();
                      }
                      if (val == null) val = "";
                      if (field == UserInterface.LDAP_USER_ENABLE) {
                        String str = val.toString();
                        Calendar now = null;
                        now = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
                        SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
                        String nowStr = df.format(now.getTime());
                        if (str.length() == 0) {
                          val = "<span style=\"color: red\">Disabled Account</span>";
                        } else if (nowStr.compareToIgnoreCase(str) < 0) {
                          val = "<span style=\"color: red\">" + val + "</span>";
                        }
                      }
            // end
            // HTML // begin [file="/user_result.jsp";from=(85,2);to=(87,14)]
                out.write("\r\n        <tr>\r\n          <td>");

            // end
            // begin [file="/user_result.jsp";from=(87,17);to=(87,22)]
                out.print(title);
            // end
            // HTML // begin [file="/user_result.jsp";from=(87,24);to=(88,14)]
                out.write("</td>\r\n          <td>");

            // end
            // begin [file="/user_result.jsp";from=(88,17);to=(88,20)]
                out.print(val);
            // end
            // HTML // begin [file="/user_result.jsp";from=(88,22);to=(90,0)]
                out.write("</td>\r\n        </tr>\r\n");

            // end
            // begin [file="/user_result.jsp";from=(90,2);to=(92,0)]
                
                      for (int j = 1; j < size; j++) {
            // end
            // HTML // begin [file="/user_result.jsp";from=(92,2);to=(95,14)]
                out.write("\r\n        <tr>\r\n          <td></td>\r\n          <td>");

            // end
            // begin [file="/user_result.jsp";from=(95,17);to=(95,28)]
                out.print(attr.get(j));
            // end
            // HTML // begin [file="/user_result.jsp";from=(95,30);to=(97,0)]
                out.write("</td>\r\n        </tr>\r\n");

            // end
            // begin [file="/user_result.jsp";from=(97,2);to=(101,0)]
                
                      }
                    }
                  }
            // end
            // HTML // begin [file="/user_result.jsp";from=(101,2);to=(104,0)]
                out.write("\r\n        <tr>\r\n          <td>Roles</td>\r\n");

            // end
            // begin [file="/user_result.jsp";from=(104,2);to=(120,0)]
                
                  NamingEnumeration roles = null;
                  boolean first = true;
                  try {
                    roles = (NamingEnumeration) request.getAttribute(UserInterface.ROLE_RESULTS);
                    while (roles.hasMore()) {
                      SearchResult sr = (SearchResult) roles.next();
                      Attributes attrs = sr.getAttributes();
                      Attribute attr = attrs.get(UserInterface.LDAP_ROLE_RDN);
                      Object val = "";
                      if (attr != null) {
                        val = attr.get();
                      }
                      if (first) {
                        first = false;
                      } else {
            // end
            // HTML // begin [file="/user_result.jsp";from=(120,2);to=(123,0)]
                out.write("\r\n        <tr>\r\n          <td></td>\r\n");

            // end
            // begin [file="/user_result.jsp";from=(123,2);to=(125,0)]
                
                      }
            // end
            // HTML // begin [file="/user_result.jsp";from=(125,2);to=(126,14)]
                out.write("\r\n          <td>");

            // end
            // begin [file="/user_result.jsp";from=(126,17);to=(126,20)]
                out.print(val);
            // end
            // HTML // begin [file="/user_result.jsp";from=(126,22);to=(128,0)]
                out.write("</td>\r\n        </tr>\r\n");

            // end
            // begin [file="/user_result.jsp";from=(128,2);to=(135,0)]
                
                    }
                  } catch (NamingException ne) {
                    ne.printStackTrace();
                    if (roles != null) roles.close();
                  }
                  if (first) { // no roles assigned to this user
            // end
            // HTML // begin [file="/user_result.jsp";from=(135,2);to=(137,0)]
                out.write("\r\n     <td></td></tr>    \r\n");

            // end
            // begin [file="/user_result.jsp";from=(137,2);to=(139,0)]
                
                  }
            // end
            // HTML // begin [file="/user_result.jsp";from=(139,2);to=(144,0)]
                out.write("\r\n      </table>\r\n    </form>\r\n  </body>\r\n</html>\r\n");

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
