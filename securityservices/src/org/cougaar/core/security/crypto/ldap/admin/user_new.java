package org.cougaar.core.security.crypto.ldap.admin;

import javax.naming.*;
import javax.naming.directory.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;
import org.apache.jasper.runtime.*;


public class user_new extends HttpJspBase {


    static {
    }
    public user_new( ) {
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

            // HTML // begin [file="/user_new.jsp";from=(0,58);to=(1,0)]
                out.write("\r\n");

            // end
            // begin [file="/user_new.jsp";from=(1,2);to=(27,0)]
                
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
            // HTML // begin [file="/user_new.jsp";from=(27,2);to=(35,12)]
                out.write("\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n<html>\r\n  <head>\r\n    <script language=\"JavaScript\">\r\n<!--\r\nfunction passwordCheck() {\r\n  var form = document.forms[0];\r\n  if (form[\"");

            // end
            // begin [file="/user_new.jsp";from=(35,15);to=(35,47)]
                out.print(UserInterface.LDAP_USER_PASSWORD);
            // end
            // HTML // begin [file="/user_new.jsp";from=(35,49);to=(36,12)]
                out.write("\"].value != \r\n      form[\"");

            // end
            // begin [file="/user_new.jsp";from=(36,15);to=(36,47)]
                out.print(UserInterface.LDAP_USER_PASSWORD);
            // end
            // HTML // begin [file="/user_new.jsp";from=(36,49);to=(49,20)]
                out.write("-repeat\"].value) {\r\n    var span = document.getElementById(\"error text\");\r\n    span.innerHTML = \"Passwords must match\";\r\n    span = document.getElementById(\"password1\");\r\n    span.setAttribute('style','color: red');\r\n    span = document.getElementById(\"password2\");\r\n    span.setAttribute('style','color: red');\r\n    return false;\r\n  }\r\n  return true;\r\n}\r\nfunction enableUser() {\r\n  var form = document.forms[0];\r\n  var field = form[\"");

            // end
            // begin [file="/user_new.jsp";from=(49,23);to=(49,53)]
                out.print(UserInterface.LDAP_USER_ENABLE);
            // end
            // HTML // begin [file="/user_new.jsp";from=(49,55);to=(54,20)]
                out.write("\"];\r\n  field.value = \"19700101000000Z\";\r\n}\r\nfunction disableUser() {\r\n  var form = document.forms[0];\r\n  var field = form[\"");

            // end
            // begin [file="/user_new.jsp";from=(54,23);to=(54,53)]
                out.print(UserInterface.LDAP_USER_ENABLE);
            // end
            // HTML // begin [file="/user_new.jsp";from=(54,55);to=(64,0)]
                out.write("\"];\r\n  field.value = \"\";\r\n}\r\nfunction cancelAction() {\r\n  history.go(-1);\r\n}\r\n// -->\r\n    </script>\r\n  </head>\r\n  <body>\r\n");

            // end
            // begin [file="/user_new.jsp";from=(64,2);to=(68,0)]
                
                  Attributes user = (Attributes) 
                    request.getAttribute(UserInterface.USER_RESULTS);
                  
            // end
            // HTML // begin [file="/user_new.jsp";from=(68,2);to=(69,18)]
                out.write("\r\n    <form action=\"");

            // end
            // begin [file="/user_new.jsp";from=(69,21);to=(69,44)]
                out.print(request.getRequestURI());
            // end
            // HTML // begin [file="/user_new.jsp";from=(69,46);to=(71,33)]
                out.write("\" method=\"POST\"\r\n          onSubmit=\"return passwordCheck();\">\r\n      <input type=\"hidden\" name=\"");

            // end
            // begin [file="/user_new.jsp";from=(71,36);to=(71,54)]
                out.print(UserInterface.PAGE);
            // end
            // HTML // begin [file="/user_new.jsp";from=(71,56);to=(72,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_new.jsp";from=(72,23);to=(72,50)]
                out.print(UserInterface.PAGE_NEW_USER);
            // end
            // HTML // begin [file="/user_new.jsp";from=(72,52);to=(73,33)]
                out.write("\">\r\n      <input type=\"submit\" name=\"");

            // end
            // begin [file="/user_new.jsp";from=(73,36);to=(73,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/user_new.jsp";from=(73,65);to=(74,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_new.jsp";from=(74,23);to=(74,59)]
                out.print(UserInterface.ACTION_BUTTON_ADD_USER);
            // end
            // HTML // begin [file="/user_new.jsp";from=(74,61);to=(75,33)]
                out.write("\">\r\n      <input type=\"button\" name=\"");

            // end
            // begin [file="/user_new.jsp";from=(75,36);to=(75,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/user_new.jsp";from=(75,65);to=(76,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_new.jsp";from=(76,23);to=(76,57)]
                out.print(UserInterface.ACTION_BUTTON_CANCEL);
            // end
            // HTML // begin [file="/user_new.jsp";from=(76,59);to=(81,14)]
                out.write("\"\r\n             onClick=\"cancelAction()\">\r\n      <br><span color=\"red\" id=\"error text\"></span><br>\r\n      <table>\r\n        <tr>\r\n          <td>");

            // end
            // begin [file="/user_new.jsp";from=(81,17);to=(81,50)]
                out.print(UserInterface.LDAP_USER_UID_TITLE);
            // end
            // HTML // begin [file="/user_new.jsp";from=(81,52);to=(82,39)]
                out.write("</td>\r\n          <td><input type=\"text\" name=\"");

            // end
            // begin [file="/user_new.jsp";from=(82,42);to=(82,69)]
                out.print(UserInterface.LDAP_USER_UID);
            // end
            // HTML // begin [file="/user_new.jsp";from=(82,71);to=(86,35)]
                out.write("\"\r\n               value=\"\"></td>\r\n        </tr>\r\n        <tr>\r\n          <td><span id=\"password1\">");

            // end
            // begin [file="/user_new.jsp";from=(86,38);to=(86,77)]
                out.print(UserInterface.LDAP_USER_PASSWORD_TITLE1);
            // end
            // HTML // begin [file="/user_new.jsp";from=(86,79);to=(88,21)]
                out.write("</span></td>\r\n          <td><input type=\"password\" \r\n               name=\"");

            // end
            // begin [file="/user_new.jsp";from=(88,24);to=(88,56)]
                out.print(UserInterface.LDAP_USER_PASSWORD);
            // end
            // HTML // begin [file="/user_new.jsp";from=(88,58);to=(92,35)]
                out.write("\" \r\n               value=\"\"></td>\r\n        </tr>\r\n        <tr>\r\n          <td><span id=\"password2\">");

            // end
            // begin [file="/user_new.jsp";from=(92,38);to=(92,77)]
                out.print(UserInterface.LDAP_USER_PASSWORD_TITLE2);
            // end
            // HTML // begin [file="/user_new.jsp";from=(92,79);to=(94,21)]
                out.write("</span></td>\r\n          <td><input type=\"password\" \r\n               name=\"");

            // end
            // begin [file="/user_new.jsp";from=(94,24);to=(94,56)]
                out.print(UserInterface.LDAP_USER_PASSWORD);
            // end
            // HTML // begin [file="/user_new.jsp";from=(94,58);to=(97,0)]
                out.write("-repeat\" \r\n               value=\"\"></td>\r\n        </tr>\r\n");

            // end
            // begin [file="/user_new.jsp";from=(97,2);to=(107,0)]
                
                    for (int i = 0; i < UserInterface.LDAP_USER_FIELDS.length; i++) {
                      String title   = UserInterface.LDAP_USER_FIELDS[i][1];
                      String field   = UserInterface.LDAP_USER_FIELDS[i][0];
                      Attribute attr = user.get(field);
                      Object val     = "";
                      if (attr != null) {
                        val = attr.get();
                      }
                      if (field != UserInterface.LDAP_USER_UID) {
            // end
            // HTML // begin [file="/user_new.jsp";from=(107,2);to=(109,14)]
                out.write("\r\n        <tr>\r\n          <td>");

            // end
            // begin [file="/user_new.jsp";from=(109,17);to=(109,22)]
                out.print(title);
            // end
            // HTML // begin [file="/user_new.jsp";from=(109,24);to=(111,0)]
                out.write("</td>\r\n          <td>\r\n");

            // end
            // begin [file="/user_new.jsp";from=(111,2);to=(114,0)]
                
                        if (field == UserInterface.LDAP_USER_AUTH) {
                          if ("".equals(val)) val = UserInterface.LDAP_USER_AUTH_VALS[UserInterface.LDAP_USER_AUTH_DEFAULT_VAL][0];
            // end
            // HTML // begin [file="/user_new.jsp";from=(114,2);to=(115,26)]
                out.write("\r\n            <select name=\"");

            // end
            // begin [file="/user_new.jsp";from=(115,29);to=(115,34)]
                out.print(field);
            // end
            // HTML // begin [file="/user_new.jsp";from=(115,36);to=(116,0)]
                out.write("\">\r\n");

            // end
            // begin [file="/user_new.jsp";from=(116,2);to=(121,0)]
                
                          for (int j = 0; j < UserInterface.LDAP_USER_AUTH_VALS.length; j++) { 
                            String selected = "";
                            if (UserInterface.LDAP_USER_AUTH_VALS[j][0].equals(val))
                              selected = " selected";
            // end
            // HTML // begin [file="/user_new.jsp";from=(121,2);to=(122,29)]
                out.write("\r\n              <option value=\"");

            // end
            // begin [file="/user_new.jsp";from=(122,32);to=(122,71)]
                out.print(UserInterface.LDAP_USER_AUTH_VALS[j][0]);
            // end
            // HTML // begin [file="/user_new.jsp";from=(122,73);to=(123,22)]
                out.write("\"\r\n                      ");

            // end
            // begin [file="/user_new.jsp";from=(123,25);to=(123,33)]
                out.print(selected);
            // end
            // HTML // begin [file="/user_new.jsp";from=(123,35);to=(124,16)]
                out.write(" >\r\n                ");

            // end
            // begin [file="/user_new.jsp";from=(124,19);to=(124,58)]
                out.print(UserInterface.LDAP_USER_AUTH_VALS[j][1]);
            // end
            // HTML // begin [file="/user_new.jsp";from=(124,60);to=(126,0)]
                out.write("\r\n              </option>\r\n");

            // end
            // begin [file="/user_new.jsp";from=(126,2);to=(126,10)]
                      } 
            // end
            // HTML // begin [file="/user_new.jsp";from=(126,12);to=(128,0)]
                out.write("\r\n            </select>\r\n");

            // end
            // begin [file="/user_new.jsp";from=(128,2);to=(130,0)]
                
                        } else if (field == UserInterface.LDAP_USER_ENABLE) {
            // end
            // HTML // begin [file="/user_new.jsp";from=(130,2);to=(131,35)]
                out.write("\r\n          <input type=\"text\" name=\"");

            // end
            // begin [file="/user_new.jsp";from=(131,38);to=(131,43)]
                out.print(field);
            // end
            // HTML // begin [file="/user_new.jsp";from=(131,45);to=(131,54)]
                out.write("\" value=\"");

            // end
            // begin [file="/user_new.jsp";from=(131,57);to=(131,60)]
                out.print(val);
            // end
            // HTML // begin [file="/user_new.jsp";from=(131,62);to=(134,0)]
                out.write("\">&nbsp;&nbsp;\r\n          <input type=\"button\" value=\"Enable\" onClick=\"enableUser();\">&nbsp;\r\n          <input type=\"button\" value=\"Disable\" onClick=\"disableUser();\">\r\n");

            // end
            // begin [file="/user_new.jsp";from=(134,2);to=(136,0)]
                
                        } else {
            // end
            // HTML // begin [file="/user_new.jsp";from=(136,2);to=(137,35)]
                out.write("\r\n          <input type=\"text\" name=\"");

            // end
            // begin [file="/user_new.jsp";from=(137,38);to=(137,43)]
                out.print(field);
            // end
            // HTML // begin [file="/user_new.jsp";from=(137,45);to=(137,54)]
                out.write("\" value=\"");

            // end
            // begin [file="/user_new.jsp";from=(137,57);to=(137,60)]
                out.print(val);
            // end
            // HTML // begin [file="/user_new.jsp";from=(137,62);to=(138,0)]
                out.write("\">\r\n");

            // end
            // begin [file="/user_new.jsp";from=(138,2);to=(140,0)]
                
                        }
            // end
            // HTML // begin [file="/user_new.jsp";from=(140,2);to=(143,0)]
                out.write("\r\n          </td>\r\n        </tr>\r\n");

            // end
            // begin [file="/user_new.jsp";from=(143,2);to=(146,0)]
                
                      }
                    }
            // end
            // HTML // begin [file="/user_new.jsp";from=(146,2);to=(151,0)]
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
