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

package org.cougaar.core.security.handoff;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.servlet.BaseServletComponent;

public class LeaveCommunityPlugin extends BaseServletComponent {
  private CommunityService cs;
  private LoggingService logging;
  private String path;

  public void load() {
    super.load();
    if (logging.isDebugEnabled()) {
      logging.debug("servlet started.");
    }
  }

  protected String getPath() {
    return path;
  }
  public void setParameter(Object o) {
    List l=(List)o;
    path=(String)l.get(0);
  }

   public void setCommunityService(CommunityService cs) {
     this.cs=cs;
   }
  public void setLoggingService(LoggingService ls) {
    this.logging=ls;
  }
    
  protected Servlet createServlet() {
    return new LeaveCommunityServlet();
  }
    
  public void unload() {
    super.unload();
    // FIXME release the rest!
  } 
  
  public void init(ServletConfig config) {
  }

  private class LeaveCommunityServlet extends HttpServlet {
    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
      throws IOException {
    if (logging.isDebugEnabled()) {
      logging.debug("doGet.");
    }

      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println("<title>Leave Community Servlet </title>");
      out.println("</head>");
      out.println("<body>");
      out.println("<H2>Leave Community Servlet</H2><BR>");
      out.println("<form action=\"\" method=\"post\">");
      out.println("Agent name: <input type=\"text\" name=\"agent\" value=\"\">");
      out.println("<br>Community name: <input type=\"text\" name=\"community\" value=\"\">");
      out.println("<br>Community manager: <input type=\"text\" name=\"manager\" value=\"\">");
      out.println("<br><input type=\"submit\"></form> ");
      out.println("</body></html>");
      out.flush();
      out.close();
    }

    public void doPost(HttpServletRequest request,
                      HttpServletResponse response)
      throws IOException {

      String agent = request.getParameter("agent");
      String community = request.getParameter("community");
      String manager = request.getParameter("manager");
      if (logging.isDebugEnabled()) {
        logging.debug("received request from " + agent + " to leave " + community);
      }
      cs.leaveCommunity(community, agent, 
        new CommunityResponseListener() {
          public void getResponse(CommunityResponse response) {
            if (response.getStatus() == CommunityResponse.SUCCESS) {
              if (logging.isInfoEnabled()) {
                logging.info("Successfully leave community.");
              }
            }
            else {
              if (logging.isInfoEnabled()) {
                logging.info("Unable to process community leave request: " + response.getStatusAsString()); 
              }
            }
          }
        });

      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");

      out.println("</body></html>");
      out.flush();
      out.close();
    }
  }
}
