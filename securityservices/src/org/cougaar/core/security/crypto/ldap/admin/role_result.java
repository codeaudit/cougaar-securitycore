package org.cougaar.core.security.crypto.ldap.admin;

import javax.naming.*;
import javax.naming.directory.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;
import org.apache.jasper.runtime.*;


public class role_result extends HttpJspBase {


    static {
    }
    public role_result( ) {
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

            // HTML // begin [file="/role_result.jsp";from=(0,58);to=(1,0)]
                out.write("\r\n");

            // end
            // begin [file="/role_result.jsp";from=(1,2);to=(27,0)]
                
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
            // HTML // begin [file="/role_result.jsp";from=(27,2);to=(40,0)]
                out.write("\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n<html>\r\n  <head>\r\n    <script language=\"JavaScript\">\r\n<!--\r\nfunction deleteCheck() {\r\n  return confirm(\"Really delete this role?\");\r\n}\r\n// -->\r\n    </script>\r\n  </head>\r\n  <body>\r\n");

            // end
            // begin [file="/role_result.jsp";from=(40,2);to=(45,0)]
                
                  Attributes role = (Attributes) 
                    request.getAttribute(UserInterface.ROLE_RESULTS);
                  
                  if (role != null) {  
            // end
            // HTML // begin [file="/role_result.jsp";from=(45,2);to=(46,18)]
                out.write("\r\n    <form action=\"");

            // end
            // begin [file="/role_result.jsp";from=(46,21);to=(46,44)]
                out.print(request.getRequestURI());
            // end
            // HTML // begin [file="/role_result.jsp";from=(46,46);to=(47,32)]
                out.write("\" method=\"GET\">\r\n     <input type=\"hidden\" name=\"");

            // end
            // begin [file="/role_result.jsp";from=(47,35);to=(47,53)]
                out.print(UserInterface.PAGE);
            // end
            // HTML // begin [file="/role_result.jsp";from=(47,55);to=(48,19)]
                out.write("\" \r\n            value=\"");

            // end
            // begin [file="/role_result.jsp";from=(48,22);to=(48,59)]
                out.print(UserInterface.PAGE_ROLE_RESULT_ACTION);
            // end
            // HTML // begin [file="/role_result.jsp";from=(48,61);to=(49,32)]
                out.write("\">\r\n     <input type=\"hidden\" name=\"");

            // end
            // begin [file="/role_result.jsp";from=(49,35);to=(49,62)]
                out.print(UserInterface.LDAP_ROLE_RDN);
            // end
            // HTML // begin [file="/role_result.jsp";from=(49,64);to=(50,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/role_result.jsp";from=(50,23);to=(50,66)]
                out.print(role.get(UserInterface.LDAP_ROLE_RDN).get());
            // end
            // HTML // begin [file="/role_result.jsp";from=(50,68);to=(51,33)]
                out.write("\">\r\n      <input type=\"submit\" name=\"");

            // end
            // begin [file="/role_result.jsp";from=(51,36);to=(51,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/role_result.jsp";from=(51,65);to=(52,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/role_result.jsp";from=(52,23);to=(52,55)]
                out.print(UserInterface.ACTION_BUTTON_EDIT);
            // end
            // HTML // begin [file="/role_result.jsp";from=(52,57);to=(53,33)]
                out.write("\">\r\n      <input type=\"submit\" name=\"");

            // end
            // begin [file="/role_result.jsp";from=(53,36);to=(53,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/role_result.jsp";from=(53,65);to=(54,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/role_result.jsp";from=(54,23);to=(54,55)]
                out.print(UserInterface.ACTION_BUTTON_COPY);
            // end
            // HTML // begin [file="/role_result.jsp";from=(54,57);to=(55,33)]
                out.write("\">\r\n      <input type=\"submit\" name=\"");

            // end
            // begin [file="/role_result.jsp";from=(55,36);to=(55,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/role_result.jsp";from=(55,65);to=(56,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/role_result.jsp";from=(56,23);to=(56,57)]
                out.print(UserInterface.ACTION_BUTTON_DELETE);
            // end
            // HTML // begin [file="/role_result.jsp";from=(56,59);to=(59,0)]
                out.write("\"\r\n             onClick=\"return deleteCheck();\">\r\n      <table>\r\n");

            // end
            // begin [file="/role_result.jsp";from=(59,2);to=(72,0)]
                
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
                //      if (val == null || val.equals(UserInterface.LDAP_ROLE_DUMMY)) val = "";
                      if (val == null) val = "";
            // end
            // HTML // begin [file="/role_result.jsp";from=(72,2);to=(74,14)]
                out.write("\r\n        <tr>\r\n          <td>");

            // end
            // begin [file="/role_result.jsp";from=(74,17);to=(74,22)]
                out.print(title);
            // end
            // HTML // begin [file="/role_result.jsp";from=(74,24);to=(75,14)]
                out.write("</td>\r\n          <td>");

            // end
            // begin [file="/role_result.jsp";from=(75,17);to=(75,20)]
                out.print(val);
            // end
            // HTML // begin [file="/role_result.jsp";from=(75,22);to=(77,0)]
                out.write("</td>\r\n        </tr>\r\n");

            // end
            // begin [file="/role_result.jsp";from=(77,2);to=(80,0)]
                
                      for (int j = 1; j < size; j++) {
                //        if (!attr.get(j).equals(UserInterface.LDAP_ROLE_DUMMY)) {
            // end
            // HTML // begin [file="/role_result.jsp";from=(80,2);to=(83,14)]
                out.write("\r\n        <tr>\r\n          <td></td>\r\n          <td>");

            // end
            // begin [file="/role_result.jsp";from=(83,17);to=(83,28)]
                out.print(attr.get(j));
            // end
            // HTML // begin [file="/role_result.jsp";from=(83,30);to=(85,0)]
                out.write("</td>\r\n        </tr>\r\n");

            // end
            // begin [file="/role_result.jsp";from=(85,2);to=(90,0)]
                
                //        }
                      }
                    }
                  }
            // end
            // HTML // begin [file="/role_result.jsp";from=(90,2);to=(95,0)]
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
