package org.cougaar.core.security.crypto.ldap.admin;

import javax.naming.*;
import javax.naming.directory.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;
import org.apache.jasper.runtime.*;


public class user_edit extends HttpJspBase {


    static {
    }
    public user_edit( ) {
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

            // HTML // begin [file="/user_edit.jsp";from=(0,58);to=(1,0)]
                out.write("\r\n");

            // end
            // begin [file="/user_edit.jsp";from=(1,2);to=(27,0)]
                
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
            // HTML // begin [file="/user_edit.jsp";from=(27,2);to=(44,12)]
                out.write("\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n<html>\r\n  <head>\r\n    <script language=\"JavaScript\">\r\n<!--\r\nfunction cancelAction() {\r\n  history.go(-1);\r\n}\r\n//-->\r\n    </script>\r\n  </head>\r\n  <head>\r\n    <script language=\"JavaScript\">\r\n<!--\r\nfunction passwordCheck() {\r\n  var form = document.forms[0];\r\n  if (form[\"");

            // end
            // begin [file="/user_edit.jsp";from=(44,15);to=(44,47)]
                out.print(UserInterface.LDAP_USER_PASSWORD);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(44,49);to=(45,12)]
                out.write("\"].value != \r\n      form[\"");

            // end
            // begin [file="/user_edit.jsp";from=(45,15);to=(45,47)]
                out.print(UserInterface.LDAP_USER_PASSWORD);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(45,49);to=(58,20)]
                out.write("-repeat\"].value) {\r\n    var span = document.getElementById(\"error text\");\r\n    span.innerHTML = \"Passwords must match\";\r\n    span = document.getElementById(\"password1\");\r\n    span.setAttribute('style','color: red');\r\n    span = document.getElementById(\"password2\");\r\n    span.setAttribute('style','color: red');\r\n    return false;\r\n  }\r\n  return true;\r\n}\r\nfunction enableUser() {\r\n  var form = document.forms[0];\r\n  var field = form[\"");

            // end
            // begin [file="/user_edit.jsp";from=(58,23);to=(58,53)]
                out.print(UserInterface.LDAP_USER_ENABLE);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(58,55);to=(63,20)]
                out.write("\"];\r\n  field.value = \"19700101000000Z\";\r\n}\r\nfunction disableUser() {\r\n  var form = document.forms[0];\r\n  var field = form[\"");

            // end
            // begin [file="/user_edit.jsp";from=(63,23);to=(63,53)]
                out.print(UserInterface.LDAP_USER_ENABLE);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(63,55);to=(70,0)]
                out.write("\"];\r\n  field.value = \"\";\r\n}\r\n// -->\r\n    </script>\r\n  </head>\r\n  <body>\r\n");

            // end
            // begin [file="/user_edit.jsp";from=(70,2);to=(75,0)]
                
                  Attributes user = (Attributes) 
                    request.getAttribute(UserInterface.USER_RESULTS);
                  
                  if (user != null) {  
            // end
            // HTML // begin [file="/user_edit.jsp";from=(75,2);to=(76,18)]
                out.write("\r\n    <form action=\"");

            // end
            // begin [file="/user_edit.jsp";from=(76,21);to=(76,44)]
                out.print(request.getRequestURI());
            // end
            // HTML // begin [file="/user_edit.jsp";from=(76,46);to=(78,33)]
                out.write("\" method=\"POST\" \r\n          onSubmit=\"return passwordCheck();\">\r\n      <input type=\"hidden\" name=\"");

            // end
            // begin [file="/user_edit.jsp";from=(78,36);to=(78,54)]
                out.print(UserInterface.PAGE);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(78,56);to=(79,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_edit.jsp";from=(79,23);to=(79,51)]
                out.print(UserInterface.PAGE_EDIT_USER);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(79,53);to=(80,33)]
                out.write("\">\r\n      <input type=\"hidden\" name=\"");

            // end
            // begin [file="/user_edit.jsp";from=(80,36);to=(80,63)]
                out.print(UserInterface.LDAP_USER_UID);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(80,65);to=(81,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_edit.jsp";from=(81,23);to=(81,66)]
                out.print(user.get(UserInterface.LDAP_USER_UID).get());
            // end
            // HTML // begin [file="/user_edit.jsp";from=(81,68);to=(82,33)]
                out.write("\">\r\n      <input type=\"submit\" name=\"");

            // end
            // begin [file="/user_edit.jsp";from=(82,36);to=(82,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(82,65);to=(83,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_edit.jsp";from=(83,23);to=(83,55)]
                out.print(UserInterface.ACTION_BUTTON_SAVE);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(83,57);to=(84,33)]
                out.write("\">\r\n      <input type=\"button\" name=\"");

            // end
            // begin [file="/user_edit.jsp";from=(84,36);to=(84,63)]
                out.print(UserInterface.ACTION_BUTTON);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(84,65);to=(85,20)]
                out.write("\" \r\n             value=\"");

            // end
            // begin [file="/user_edit.jsp";from=(85,23);to=(85,57)]
                out.print(UserInterface.ACTION_BUTTON_CANCEL);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(85,59);to=(90,14)]
                out.write("\"\r\n             onClick=\"cancelAction()\">\r\n      <br><span color=\"red\" id=\"error text\"></span><br>\r\n      <table>\r\n        <tr>\r\n          <td>");

            // end
            // begin [file="/user_edit.jsp";from=(90,17);to=(90,50)]
                out.print(UserInterface.LDAP_USER_UID_TITLE);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(90,52);to=(91,14)]
                out.write("</td>\r\n          <td>");

            // end
            // begin [file="/user_edit.jsp";from=(91,17);to=(91,60)]
                out.print(user.get(UserInterface.LDAP_USER_UID).get());
            // end
            // HTML // begin [file="/user_edit.jsp";from=(91,62);to=(94,35)]
                out.write("</td>\r\n        </tr>\r\n        <tr>\r\n          <td><span id=\"password1\">");

            // end
            // begin [file="/user_edit.jsp";from=(94,38);to=(94,77)]
                out.print(UserInterface.LDAP_USER_PASSWORD_TITLE1);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(94,79);to=(96,21)]
                out.write("</span></td>\r\n          <td><input type=\"password\" \r\n               name=\"");

            // end
            // begin [file="/user_edit.jsp";from=(96,24);to=(96,56)]
                out.print(UserInterface.LDAP_USER_PASSWORD);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(96,58);to=(100,35)]
                out.write("\" \r\n               value=\"\"></td>\r\n        </tr>\r\n        <tr>\r\n          <td><span id=\"password2\">");

            // end
            // begin [file="/user_edit.jsp";from=(100,38);to=(100,77)]
                out.print(UserInterface.LDAP_USER_PASSWORD_TITLE2);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(100,79);to=(102,21)]
                out.write("</span></td>\r\n          <td><input type=\"password\" \r\n               name=\"");

            // end
            // begin [file="/user_edit.jsp";from=(102,24);to=(102,56)]
                out.print(UserInterface.LDAP_USER_PASSWORD);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(102,58);to=(105,0)]
                out.write("-repeat\" \r\n               value=\"\"></td>\r\n        </tr>\r\n");

            // end
            // begin [file="/user_edit.jsp";from=(105,2);to=(115,0)]
                
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
            // HTML // begin [file="/user_edit.jsp";from=(115,2);to=(117,14)]
                out.write("\r\n        <tr>\r\n          <td>");

            // end
            // begin [file="/user_edit.jsp";from=(117,17);to=(117,22)]
                out.print(title);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(117,24);to=(119,0)]
                out.write("</td>\r\n          <td>\r\n");

            // end
            // begin [file="/user_edit.jsp";from=(119,2);to=(122,0)]
                
                        if (field == UserInterface.LDAP_USER_AUTH) {
                          if ("".equals(val)) val = UserInterface.LDAP_USER_AUTH_VALS[UserInterface.LDAP_USER_AUTH_DEFAULT_VAL][0];
            // end
            // HTML // begin [file="/user_edit.jsp";from=(122,2);to=(123,26)]
                out.write("\r\n            <select name=\"");

            // end
            // begin [file="/user_edit.jsp";from=(123,29);to=(123,34)]
                out.print(field);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(123,36);to=(124,0)]
                out.write("\">\r\n");

            // end
            // begin [file="/user_edit.jsp";from=(124,2);to=(129,0)]
                
                          for (int j = 0; j < UserInterface.LDAP_USER_AUTH_VALS.length; j++) { 
                            String selected = "";
                            if (UserInterface.LDAP_USER_AUTH_VALS[j][0].equals(val))
                              selected = " selected";
            // end
            // HTML // begin [file="/user_edit.jsp";from=(129,2);to=(130,29)]
                out.write("\r\n              <option value=\"");

            // end
            // begin [file="/user_edit.jsp";from=(130,32);to=(130,71)]
                out.print(UserInterface.LDAP_USER_AUTH_VALS[j][0]);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(130,73);to=(131,22)]
                out.write("\"\r\n                      ");

            // end
            // begin [file="/user_edit.jsp";from=(131,25);to=(131,33)]
                out.print(selected);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(131,35);to=(132,16)]
                out.write(" >\r\n                ");

            // end
            // begin [file="/user_edit.jsp";from=(132,19);to=(132,58)]
                out.print(UserInterface.LDAP_USER_AUTH_VALS[j][1]);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(132,60);to=(134,0)]
                out.write("\r\n              </option>\r\n");

            // end
            // begin [file="/user_edit.jsp";from=(134,2);to=(134,10)]
                      } 
            // end
            // HTML // begin [file="/user_edit.jsp";from=(134,12);to=(136,0)]
                out.write("\r\n            </select>\r\n");

            // end
            // begin [file="/user_edit.jsp";from=(136,2);to=(138,0)]
                
                        } else if (field == UserInterface.LDAP_USER_ENABLE) {
            // end
            // HTML // begin [file="/user_edit.jsp";from=(138,2);to=(139,35)]
                out.write("\r\n          <input type=\"text\" name=\"");

            // end
            // begin [file="/user_edit.jsp";from=(139,38);to=(139,43)]
                out.print(field);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(139,45);to=(139,54)]
                out.write("\" value=\"");

            // end
            // begin [file="/user_edit.jsp";from=(139,57);to=(139,60)]
                out.print(val);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(139,62);to=(142,0)]
                out.write("\">&nbsp;&nbsp;\r\n          <input type=\"button\" value=\"Enable\" onClick=\"enableUser();\">&nbsp;\r\n          <input type=\"button\" value=\"Disable\" onClick=\"disableUser();\">\r\n");

            // end
            // begin [file="/user_edit.jsp";from=(142,2);to=(144,0)]
                
                        } else {
            // end
            // HTML // begin [file="/user_edit.jsp";from=(144,2);to=(145,35)]
                out.write("\r\n          <input type=\"text\" name=\"");

            // end
            // begin [file="/user_edit.jsp";from=(145,38);to=(145,43)]
                out.print(field);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(145,45);to=(145,54)]
                out.write("\" value=\"");

            // end
            // begin [file="/user_edit.jsp";from=(145,57);to=(145,60)]
                out.print(val);
            // end
            // HTML // begin [file="/user_edit.jsp";from=(145,62);to=(146,0)]
                out.write("\">\r\n");

            // end
            // begin [file="/user_edit.jsp";from=(146,2);to=(148,0)]
                
                        }
            // end
            // HTML // begin [file="/user_edit.jsp";from=(148,2);to=(151,0)]
                out.write("\r\n          </td>\r\n        </tr>\r\n");

            // end
            // begin [file="/user_edit.jsp";from=(151,2);to=(155,0)]
                
                      }
                    }
                  }
            // end
            // HTML // begin [file="/user_edit.jsp";from=(155,2);to=(160,0)]
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
