package org.cougaar.core.security.crypto.ldap.admin;

import javax.naming.*;
import javax.naming.directory.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;
import org.apache.jasper.runtime.*;


public class search_users extends HttpJspBase {


    static {
    }
    public search_users( ) {
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

            // HTML // begin [file="/search_users.jsp";from=(0,69);to=(1,0)]
                out.write("\r\n");

            // end
            // begin [file="/search_users.jsp";from=(1,2);to=(27,0)]
                
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
            // HTML // begin [file="/search_users.jsp";from=(27,2);to=(35,0)]
                out.write("\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n<html>\r\n  <body>\r\n    <table width=\"100%\">\r\n      <tr>\r\n        <td colspan=\"3\">Users matching your search:</td>\r\n      </tr>\r\n");

            // end
            // begin [file="/search_users.jsp";from=(35,2);to=(39,0)]
                
                  NamingEnumeration users = null;
                  try {
                    users = (NamingEnumeration) request.getAttribute(UserInterface.SEARCH_RESULTS);
            // end
            // HTML // begin [file="/search_users.jsp";from=(39,2);to=(41,0)]
                out.write("\r\n      <tr>\r\n");

            // end
            // begin [file="/search_users.jsp";from=(41,2);to=(43,0)]
                
                    for (int i = 0; i < UserInterface.LDAP_SEARCH_FIELDS.length; i++) {
            // end
            // HTML // begin [file="/search_users.jsp";from=(43,2);to=(44,15)]
                out.write("\r\n        <td><b>");

            // end
            // begin [file="/search_users.jsp";from=(44,18);to=(44,56)]
                out.print(UserInterface.LDAP_SEARCH_FIELDS[i][1]);
            // end
            // HTML // begin [file="/search_users.jsp";from=(44,58);to=(45,0)]
                out.write("</b></td>\r\n");

            // end
            // begin [file="/search_users.jsp";from=(45,2);to=(47,0)]
                
                    }
            // end
            // HTML // begin [file="/search_users.jsp";from=(47,2);to=(49,0)]
                out.write("\r\n      </tr>\r\n");

            // end
            // begin [file="/search_users.jsp";from=(49,2);to=(51,0)]
                
                    while (users.hasMore()) {
            // end
            // HTML // begin [file="/search_users.jsp";from=(51,2);to=(53,0)]
                out.write("\r\n      <tr>\r\n");

            // end
            // begin [file="/search_users.jsp";from=(53,2);to=(61,0)]
                
                      SearchResult user = (SearchResult) users.next();
                      Attributes attrs = user.getAttributes();
                      String uid = attrs.get(UserInterface.LDAP_USER_UID).get().toString();
                      for (int i = 0; i < UserInterface.LDAP_SEARCH_FIELDS.length; i++) {
                        Attribute attr = attrs.get(UserInterface.LDAP_SEARCH_FIELDS[i][0]);
                        String val = "";
                        if (attr != null) val = attr.get().toString();
            // end
            // HTML // begin [file="/search_users.jsp";from=(61,2);to=(63,0)]
                out.write("\r\n        <td>\r\n");

            // end
            // begin [file="/search_users.jsp";from=(63,2);to=(65,0)]
                 
                        if (i == 0) {
            // end
            // HTML // begin [file="/search_users.jsp";from=(65,2);to=(65,11)]
                out.write("<a href=\"");

            // end
            // begin [file="/search_users.jsp";from=(65,14);to=(66,72)]
                out.print(request.getRequestURI() + "?" +
              UserInterface.PAGE + "=" + UserInterface.PAGE_DISPLAY_USER);
            // end
            // HTML // begin [file="/search_users.jsp";from=(66,74);to=(66,75)]
                out.write("&");

            // end
            // begin [file="/search_users.jsp";from=(66,78);to=(66,124)]
                out.print(URLEncoder.encode(UserInterface.LDAP_USER_UID, "UTF-8"));
            // end
            // HTML // begin [file="/search_users.jsp";from=(66,126);to=(66,127)]
                out.write("=");

            // end
            // begin [file="/search_users.jsp";from=(66,130);to=(66,152)]
                out.print(URLEncoder.encode(uid, "UTF-8"));
            // end
            // HTML // begin [file="/search_users.jsp";from=(66,154);to=(67,39)]
                out.write("\" \r\n               target=\"UserMatchFrame\">");

            // end
            // begin [file="/search_users.jsp";from=(67,41);to=(69,0)]
                
                        } 
            // end
            // begin [file="/search_users.jsp";from=(69,5);to=(69,8)]
                out.print(val);
            // end
            // begin [file="/search_users.jsp";from=(69,12);to=(71,0)]
                
                        if (i == 1) {
            // end
            // HTML // begin [file="/search_users.jsp";from=(71,2);to=(71,6)]
                out.write("</a>");

            // end
            // begin [file="/search_users.jsp";from=(71,8);to=(73,0)]
                
                        }
            // end
            // HTML // begin [file="/search_users.jsp";from=(73,2);to=(74,0)]
                out.write("</td>\r\n");

            // end
            // begin [file="/search_users.jsp";from=(74,2);to=(76,0)]
                
                      }
            // end
            // HTML // begin [file="/search_users.jsp";from=(76,2);to=(78,0)]
                out.write("\r\n      </tr>\r\n");

            // end
            // begin [file="/search_users.jsp";from=(78,2);to=(85,0)]
                
                    }
                  } catch (NamingException ne) {
                    if (users != null) {
                      users.close();
                    }
                  }
            // end
            // HTML // begin [file="/search_users.jsp";from=(85,2);to=(89,0)]
                out.write("\r\n    </table>\r\n  </body>\r\n</html>\r\n");

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
