package org.cougaar.core.security.crypto.ldap.admin;

import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;
import org.apache.jasper.runtime.*;


public class error extends HttpJspBase {


    static {
    }
    public error( ) {
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

            // begin [file="/error.jsp";from=(0,2);to=(26,0)]
                
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
            // HTML // begin [file="/error.jsp";from=(26,2);to=(31,0)]
                out.write("\r\n<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n<html>\r\n  <body>\r\n    <h1>Error</h1>\r\n");

            // end
            // begin [file="/error.jsp";from=(31,2);to=(34,0)]
                
                  Exception e = (Exception) request.getAttribute("exception");
                  if (e != null) {
            // end
            // HTML // begin [file="/error.jsp";from=(34,2);to=(37,0)]
                out.write("\r\nException when exceuting command:\r\n<pre>\r\n");

            // end
            // begin [file="/error.jsp";from=(37,2);to=(39,0)]
                
                    e.printStackTrace(new java.io.PrintWriter(out));
            // end
            // HTML // begin [file="/error.jsp";from=(39,2);to=(41,0)]
                out.write("\r\n</pre>\r\n");

            // end
            // begin [file="/error.jsp";from=(41,2);to=(43,0)]
                
                  }
            // end
            // HTML // begin [file="/error.jsp";from=(43,2);to=(46,0)]
                out.write("\r\n  </body>\r\n</html>\r\n");

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
