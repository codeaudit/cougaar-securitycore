/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

package org.cougaar.core.security.crypto.servlet;

// Imported java classes
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.crypto.blackboard.InUseDNObject;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.util.UnaryPredicate;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;



public class PublishedDNViewerComponent extends BaseServletComponent implements BlackboardClient  {
  private MessageAddress agentId;
  private AgentIdentificationService ais;
  private BlackboardService blackboard;
  private LoggingService logging;
  private String path;

  public void load() {
    super.load();
  }

  protected String getPath() {
    return path;
  }
  public void setParameter(Object o) {
    List l=(List)o;
    path=(String)l.get(0);
  }

  public void setBlackboardService(BlackboardService blackboard) {
    this.blackboard = blackboard;
  }

  public void setAgentIdentificationService( AgentIdentificationService agentis){
    if(agentis!=null) {
      this.ais=agentis;
      agentId = ais.getMessageAddress(); 
    }
  }
  
  public void setLoggingService(LoggingService ls) {
    this.logging=ls;
  }
  
  protected Servlet createServlet() {
    if(ais!=null) {
      agentId = ais.getMessageAddress(); 
    }
    else {
      if(logging.isDebugEnabled()) {
        logging.debug("  createServlet()called  in PublishedDNViewerComponent and ais is null ");
      }
    }
    
    return new DNViewerServlet();
  }

  public void unload() {
    super.unload();
    // FIXME release the rest!
  }

  public void init(ServletConfig config)
    throws ServletException {
    if(logging.isDebugEnabled()) {
      logging.debug("  init(ServletConfig config)called  in PublishedDNViewerComponent");
    }
    ais = (AgentIdentificationService)
      serviceBroker.getService(this, AgentIdentificationService.class, null);
    if(ais!=null) {
      agentId = ais.getMessageAddress();
    }
    else {
      if(logging.isDebugEnabled()) {
        logging.debug("  init() called  in PublishedDNViewerComponent and ais is null ");
      }
    }
  }

  public String getBlackboardClientName() {
    return toString();
  }

  // odd BlackboardClient method:
  public long currentTimeMillis() {
    throw new UnsupportedOperationException(
      this+" asked for the current time???");
  }

  // unused BlackboardClient method:
  public boolean triggerEvent(Object event) {
    // if we had Subscriptions we'd need to implement this.
    //
    // see "ComponentPlugin" for details.
    throw new UnsupportedOperationException(
      this+" only supports Blackboard queries, but received "+
      "a \"trigger\" event: "+event);
  }

  private class DNViewerServlet extends HttpServlet {
    
    class InUseDNPredicate implements UnaryPredicate {
      /** @return true if the object "passes" the predicate */
      public boolean execute(Object o) {
	boolean ret = false;
	if (o instanceof InUseDNObject ) {
	  return true;
	}
	return ret;
      }
    }
    
    public void doGet(HttpServletRequest request,
		      HttpServletResponse response)
      throws IOException {
      if (ais == null) {
	ais = (AgentIdentificationService)
	  serviceBroker.getService(this, AgentIdentificationService.class, null);
	agentId = ais.getMessageAddress();
      }

      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println("<title>In Use DN  Viewer </title>");
      out.println("</head>");
      out.println("<body>");
      out.println("<H2>In Use DN  Viewer</H2><BR>");
      String result= null;
      Collection dnCollection=null;
      try {
	out.println("<H3> Query of the Blackboard started  :"
		    + agentId.toAddress() +"</H3>");
	out.flush();
	blackboard.openTransaction();
        dnCollection=blackboard.query(new InUseDNPredicate());
	out.println("<H3> Query of the Blackboard Completed   :"
		    + agentId.toAddress() +"</H3>");
	out.flush();
      }
      catch(Exception exp) {
	out.println("<H3> Exception has occured at  :"
		    + agentId.toAddress()+ "Messgae :"
		    + exp.getMessage() +"</H3>");
	out.flush();
      }
      finally {
	blackboard.closeTransaction();
      }
      if((dnCollection==null)||dnCollection.isEmpty()) {
	out.println("No published DN  are currently present ");
	out.flush();
	out.close();
	return;
      }
      result=createTable(dnCollection );
      out.println( result);
      out.println("</body></html>");
      out.flush();
      out.close();
   

    }

    public String createTable(Collection  dnCollection) {
      StringBuffer sb=new StringBuffer();
      sb.append("<table align=\"center\" border=\"2\">\n");
      sb.append("<TR><TH> Agent Name  </TH><TH> Used DNs </TH></TR>\n");
      sb.append("<TR><TD>\n");
      sb.append(agentId.toAddress());
      sb.append("</TD>\n");
      sb.append("<TD>\n");
      sb.append("<UL>");      
      Iterator it = dnCollection.iterator();      
      InUseDNObject dnobject=null;
      while(it.hasNext()) {
        dnobject=(InUseDNObject) it.next();
        sb.append("<LI>"+ dnobject.getDNName()+"\n");
      }
      sb.append("</UL>\n");
      sb.append("</TD>\n");
      sb.append("</table>");
      return sb.toString();
    }
  }

}
