package org.cougaar.core.security.crypto.ldap.admin;

import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;
import org.apache.jasper.runtime.*;


public class role extends HttpJspBase {


    static {
    }
    public role( ) {
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

            // begin [file="/role.jsp";from=(0,2);to=(26,0)]
                
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
            // HTML // begin [file="/role.jsp";from=(26,2);to=(33,46)]
                out.write("\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n<html>\r\n  <head>\r\n    <title>Role Edit</title>\r\n<script language=\"JavaScript\">\r\nfunction newRole() {\r\n  top.frames['UserMatchFrame'].location.href='");

            // end
            // begin [file="/role.jsp";from=(33,49);to=(33,139)]
                out.print(request.getRequestURI() + "?" + UserInterface.PAGE + "=" + UserInterface.PAGE_NEW_ROLE_JSP);
            // end
            // HTML // begin [file="/role.jsp";from=(33,141);to=(41,35)]
                out.write("';\r\n}\r\n</script>\r\n  </head>\r\n\r\n  <body>\r\n    <table width=\"100%\">\r\n      <tr>\r\n        <td align=\"right\"><a href=\"");

            // end
            // begin [file="/role.jsp";from=(41,38);to=(43,52)]
                out.print(request.getRequestURI() + "?" +
                      UserInterface.PAGE + "=" +
                      UserInterface.PAGE_SEARCH_USER);
            // end
            // HTML // begin [file="/role.jsp";from=(43,54);to=(48,18)]
                out.write("\">Users</a></td>\r\n        <td align=\"center\">|</td>\r\n        <td align=\"left\"><b>Roles</b></td>\r\n      </tr>\r\n    </table>\r\n    <form action=\"");

            // end
            // begin [file="/role.jsp";from=(48,21);to=(48,44)]
                out.print(request.getRequestURI());
            // end
            // HTML // begin [file="/role.jsp";from=(48,46);to=(50,33)]
                out.write("\"\r\n          target=\"SearchResultsFrame\" method=\"GET\">\r\n      <input type=\"hidden\" name=\"");

            // end
            // begin [file="/role.jsp";from=(50,36);to=(50,54)]
                out.print(UserInterface.PAGE);
            // end
            // HTML // begin [file="/role.jsp";from=(50,56);to=(51,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/role.jsp";from=(51,23);to=(51,54)]
                out.print(UserInterface.PAGE_RESULTS_ROLE);
            // end
            // HTML // begin [file="/role.jsp";from=(51,56);to=(55,39)]
                out.write("\">\r\n      <table width=\"100%\">\r\n        <tr>\r\n          <td>Search Term</td>\r\n          <td><input type=\"text\" name=\"");

            // end
            // begin [file="/role.jsp";from=(55,42);to=(55,67)]
                out.print(UserInterface.SEARCH_TERM);
            // end
            // HTML // begin [file="/role.jsp";from=(55,69);to=(60,26)]
                out.write("\"></td>\r\n        </tr>\r\n        <tr>\r\n          <td>Search On</td>\r\n          <td>\r\n            <select name=\"");

            // end
            // begin [file="/role.jsp";from=(60,29);to=(60,55)]
                out.print(UserInterface.SEARCH_FIELD);
            // end
            // HTML // begin [file="/role.jsp";from=(60,57);to=(61,0)]
                out.write("\">\r\n");

            // end
            // begin [file="/role.jsp";from=(61,2);to=(64,0)]
                 for (int i = 0; i < UserInterface.LDAP_ROLE_FIELDS.length; i++) {
                     String ldapName = UserInterface.LDAP_ROLE_FIELDS[i][0];
                     String visName = UserInterface.LDAP_ROLE_FIELDS[i][1];
            // end
            // HTML // begin [file="/role.jsp";from=(64,2);to=(65,29)]
                out.write("\r\n              <option value=\"");

            // end
            // begin [file="/role.jsp";from=(65,32);to=(65,40)]
                out.print(ldapName);
            // end
            // HTML // begin [file="/role.jsp";from=(65,42);to=(65,44)]
                out.write("\">");

            // end
            // begin [file="/role.jsp";from=(65,47);to=(65,54)]
                out.print(visName);
            // end
            // HTML // begin [file="/role.jsp";from=(65,56);to=(66,0)]
                out.write("</option>\r\n");

            // end
            // begin [file="/role.jsp";from=(66,2);to=(66,5)]
                 } 
            // end
            // HTML // begin [file="/role.jsp";from=(66,7);to=(73,26)]
                out.write("\r\n            </select>\r\n          </td>\r\n        </tr>\r\n        <tr>\r\n          <td>Maximum Results</td>\r\n          <td>\r\n            <select name=\"");

            // end
            // begin [file="/role.jsp";from=(73,29);to=(73,61)]
                out.print(UserInterface.SEARCH_MAX_RESULTS);
            // end
            // HTML // begin [file="/role.jsp";from=(73,63);to=(85,40)]
                out.write("\">\r\n              <option value=\"10\">10</option>\r\n              <option value=\"25\">25</option>\r\n              <option value=\"50\">50</option>\r\n              <option value=\"100\" selected>100</option>\r\n              <option value=\"200\">200</option>\r\n              <option value=\"500\">500</option>\r\n            </select>\r\n          </td>\r\n        </tr>\r\n        <tr>\r\n          <td align=\"left\">\r\n            <input type=\"button\" value=\"");

            // end
            // begin [file="/role.jsp";from=(85,43);to=(85,74)]
                out.print(UserInterface.ACTION_BUTTON_NEW);
            // end
            // HTML // begin [file="/role.jsp";from=(85,76);to=(89,39)]
                out.write("\" \r\n                   onClick=\"newRole()\">\r\n          </td>\r\n          <td align=\"right\">\r\n            <input type=\"submit\" name=\"");

            // end
            // begin [file="/role.jsp";from=(89,42);to=(89,69)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/role.jsp";from=(89,71);to=(90,20)]
                out.write("\"\r\n             value=\"");

            // end
            // begin [file="/role.jsp";from=(90,23);to=(90,57)]
                out.print(UserInterface.ACTION_BUTTON_SEARCH);
            // end
            // HTML // begin [file="/role.jsp";from=(90,59);to=(97,0)]
                out.write("\">\r\n          </td>\r\n        </tr>\r\n      </table>\r\n    </form>\r\n  </body>\r\n</html>\r\n");

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
