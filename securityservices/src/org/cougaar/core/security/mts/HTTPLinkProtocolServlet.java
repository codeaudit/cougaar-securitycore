/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
 
package org.cougaar.core.security.mts;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.servlet.ComponentServlet;
import org.cougaar.mts.base.CommFailureException;
import org.cougaar.mts.base.MisdeliveredMessageException;
import org.cougaar.mts.std.AttributedMessage;

public class HTTPLinkProtocolServlet extends ComponentServlet {
  protected String getPath() {
    return "/httpmts";
  }

  public void usage(HttpServletResponse resp) 
    throws IOException {
    resp.setContentType("text/html");
    PrintWriter out = resp.getWriter();
    out.println("<html><head><title>HTTP MTS Servlet</title></head>");
    out.println("<body><h1>HTTP MTS Servlet</h1>");
    out.println("This Servlet is only for use by the HTTPLinkProtocol.");
    out.println("</body></html>");
  }

  public void service(HttpServletRequest req, HttpServletResponse resp) 
    throws IOException {
    String enc = req.getParameter("m");
    if (enc == null) {
      usage(resp);
      return;
    }
    byte[] buf = enc.getBytes();
    Object result;
    try {
      Object obj = HTTPLinkProtocol.convertFromBytes(buf);
      if (!(obj instanceof AttributedMessage)) {
        Exception e = 
          new IllegalArgumentException("send message of class: " +
                                       obj.getClass().getName());
        result = new CommFailureException(e);
      } else {
        AttributedMessage message = (AttributedMessage) obj;
        result = HTTPLinkProtocol.getLink().deliverMessage(message);
      }
    } catch (MisdeliveredMessageException e) {
      result = e;
    } catch (Exception e) {
      result = new CommFailureException(e);
    }
    buf = HTTPLinkProtocol.convertToBytes(result);
    resp.setContentType("text/plain");
    resp.getOutputStream().write(buf);
  }
}
