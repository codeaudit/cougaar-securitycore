/*
 * <copyright>
 *  Copyright 1997-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * Created on May 08, 2002, 2:42 PM
 */

package org.cougaar.core.security.test.message;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Iterator;
import java.io.PrintWriter;
import java.io.IOException;

import org.cougaar.core.security.test.AbstractServletComponent;

public class CrlMessageBinderServlet
  extends AbstractServletComponent
{
  /**
   * returns the path for the servlet
   *
   * @return servlet path
   */
  protected String getPath() {
    return "/crlMessageBinderServlet";
  }

  protected void execute(HttpServletRequest req, HttpServletResponse resp) {
    String param = req.getParameter("crlEnqueueMsg");
    boolean enqueue = Boolean.valueOf(param).booleanValue();

    try {
      PrintWriter out = resp.getWriter();
      resp.setContentType("text/html");

      out.println("<html>\n" +
		  "<head><title>CRL Message binder servlet</title></head>\n" +
		  "<body><h1>CRL Message binder servlet</h1>");

      if (param == null || param.equals("")) {
	out.println("Current setup - Enqueuing CRL messages: " + 
		    CrlMessageBinder.getQueueCrls() + "<br/><br/>");
	out.println("Invoke the servlet with the following parameter:<br/>");
	out.println("crlEnqueueMsg: true - enqueue CRL messages <br/>");
	out.println("crlEnqueueMsg: false - do not enqueue CRL messages and deliver queued CRLs<br/>");
      }
      else {
	out.println("Success - Enqueuing CRL messages: " + enqueue + "<br/>");
	CrlMessageBinder.queueCrls(enqueue);
      }
      out.println("</body></html>");
      out.flush();
      out.close();
    }
    catch (IOException e) {
    }
  }
}
