package org.cougaar.core.security.crypto.ldap.admin;

import org.cougaar.core.security.crypto.ldap.admin.UserInterface;
import javax.naming.*;
import javax.naming.directory.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;
import org.apache.jasper.runtime.*;


public class role_edit extends HttpJspBase {


    static {
    }
    public role_edit( ) {
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

            // HTML // begin [file="/role_edit.jsp";from=(0,116);to=(1,0)]
                out.write("\r\n");

            // end
            // begin [file="/role_edit.jsp";from=(1,2);to=(27,0)]
                
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
            // HTML // begin [file="/role_edit.jsp";from=(27,2);to=(40,0)]
                out.write("\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n<html>\r\n  <head>\r\n    <script language=\"JavaScript\">\r\n<!--\r\nfunction cancelAction() {\r\n  history.go(-1);\r\n}\r\n//-->\r\n    </script>\r\n  </head>\r\n  <body>\r\n");

            // end
            // begin [file="/role_edit.jsp";from=(40,2);to=(45,0)]
                
                  Attributes role = (Attributes) 
                    request.getAttribute(UserInterface.ROLE_RESULTS);
                  
                  if (role != null) {  
            // end
            // HTML // begin [file="/role_edit.jsp";from=(45,2);to=(46,18)]
                out.write("\r\n    <form action=\"");

            // end
            // begin [file="/role_edit.jsp";from=(46,21);to=(46,44)]
                out.print(request.getRequestURI());
            // end
            // HTML // begin [file="/role_edit.jsp";from=(46,46);to=(47,33)]
                out.write("\" method=\"POST\">\r\n      <input type=\"hidden\" name=\"");

            // end
            // begin [file="/role_edit.jsp";from=(47,36);to=(47,54)]
                out.print(UserInterface.PAGE);
            // end
            // HTML // begin [file="/role_edit.jsp";from=(47,56);to=(48,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/role_edit.jsp";from=(48,23);to=(48,51)]
                out.print(UserInterface.PAGE_EDIT_ROLE);
            // end
            // HTML // begin [file="/role_edit.jsp";from=(48,53);to=(49,33)]
                out.write("\">\r\n      <input type=\"hidden\" name=\"");

            // end
            // begin [file="/role_edit.jsp";from=(49,36);to=(49,63)]
                out.print(UserInterface.LDAP_ROLE_RDN);
            // end
            // HTML // begin [file="/role_edit.jsp";from=(49,65);to=(50,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/role_edit.jsp";from=(50,23);to=(50,66)]
                out.print(role.get(UserInterface.LDAP_ROLE_RDN).get());
            // end
            // HTML // begin [file="/role_edit.jsp";from=(50,68);to=(51,33)]
                out.write("\">\r\n      <input type=\"submit\" name=\"");

            // end
            // begin [file="/role_edit.jsp";from=(51,36);to=(51,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/role_edit.jsp";from=(51,65);to=(52,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/role_edit.jsp";from=(52,23);to=(52,55)]
                out.print(UserInterface.ACTION_BUTTON_SAVE);
            // end
            // HTML // begin [file="/role_edit.jsp";from=(52,57);to=(53,33)]
                out.write("\">\r\n      <input type=\"button\" name=\"");

            // end
            // begin [file="/role_edit.jsp";from=(53,36);to=(53,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/role_edit.jsp";from=(53,65);to=(54,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/role_edit.jsp";from=(54,23);to=(54,57)]
                out.print(UserInterface.ACTION_BUTTON_CANCEL);
            // end
            // HTML // begin [file="/role_edit.jsp";from=(54,59);to=(57,0)]
                out.write("\"\r\n             onClick=\"cancelAction()\">\r\n      <table>\r\n");

            // end
            // begin [file="/role_edit.jsp";from=(57,2);to=(70,0)]
                
                    for (int i = 0; i < UserInterface.LDAP_ROLE_FIELDS.length; i++) {
                      String title   = UserInterface.LDAP_ROLE_FIELDS[i][1];
                      String field   = UserInterface.LDAP_ROLE_FIELDS[i][0];
                      Attribute attr = role.get(field);
                      Object val     = null;
                      int size = 0;
                      if (attr != null) {
                        val = attr.get();
                        size = attr.size();
                      }
                      if (val == null) val = "";
                      if (field != UserInterface.LDAP_ROLE_USER_RDN) {
            // end
            // HTML // begin [file="/role_edit.jsp";from=(70,2);to=(72,14)]
                out.write("\r\n        <tr>\r\n          <td>");

            // end
            // begin [file="/role_edit.jsp";from=(72,17);to=(72,22)]
                out.print(title);
            // end
            // HTML // begin [file="/role_edit.jsp";from=(72,24);to=(73,14)]
                out.write("</td>\r\n          <td>");

            // end
            // begin [file="/role_edit.jsp";from=(73,16);to=(75,0)]
                
                        if (field == UserInterface.LDAP_ROLE_RDN) {
            // end
            // HTML // begin [file="/role_edit.jsp";from=(75,2);to=(76,12)]
                out.write("\r\n            ");

            // end
            // begin [file="/role_edit.jsp";from=(76,15);to=(76,18)]
                out.print(val);
            // end
            // HTML // begin [file="/role_edit.jsp";from=(76,20);to=(77,0)]
                out.write("\r\n");

            // end
            // begin [file="/role_edit.jsp";from=(77,2);to=(79,0)]
                
                        } else {
            // end
            // HTML // begin [file="/role_edit.jsp";from=(79,2);to=(80,37)]
                out.write("\r\n            <input type=\"text\" name=\"");

            // end
            // begin [file="/role_edit.jsp";from=(80,40);to=(80,45)]
                out.print(field);
            // end
            // HTML // begin [file="/role_edit.jsp";from=(80,47);to=(80,56)]
                out.write("\" value=\"");

            // end
            // begin [file="/role_edit.jsp";from=(80,59);to=(80,62)]
                out.print(val);
            // end
            // HTML // begin [file="/role_edit.jsp";from=(80,64);to=(81,0)]
                out.write("\">\r\n");

            // end
            // begin [file="/role_edit.jsp";from=(81,2);to=(83,0)]
                
                        }
            // end
            // HTML // begin [file="/role_edit.jsp";from=(83,2);to=(85,0)]
                out.write("        </td>\r\n        </tr>\r\n");

            // end
            // begin [file="/role_edit.jsp";from=(85,2);to=(89,0)]
                
                      }
                    }
                  }
            // end
            // HTML // begin [file="/role_edit.jsp";from=(89,2);to=(95,0)]
                out.write("\r\n      </table>\r\n    </form>\r\n  </body>\r\n</html>\r\n\r\n");

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
