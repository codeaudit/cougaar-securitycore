
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

package org.cougaar.core.security.crypto.crl.servlet;

// Imported java classes
import java.io.*;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Enumeration;
import java.util.Vector;
import javax.servlet.*;
import javax.servlet.http.*;


// Cougaar core services

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.component.*;
import org.cougaar.core.service.*;
import org.cougaar.core.service.community.*;
import org.cougaar.core.servlet.BaseServletComponent;

import org.cougaar.core.servlet.SimpleServletSupport;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.util.*;

// Cougaar security services
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.crypto.crl.blackboard.*;



/**
 *  Use the TraX interface to perform a transformation.
 */
public class CRLRegistrationInfo extends BaseServletComponent implements BlackboardClient  {

  private AgentIdentificationService ais;
  private MessageAddress agentId;
  private BlackboardService blackboard;
  private DomainService ds;
  private CommunityService cs;
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

  public void setDomainService(DomainService ds) {
    this.ds = ds;
  }
  
   public void setCommunityService(CommunityService cs) {
     this.cs=cs;
   }
  public void setLoggingService(LoggingService ls) {
    this.logging=ls;
  }
  
  protected Servlet createServlet() {
    return new CRLRegistrationViewerServlet();
  }

  public void unload() {
    super.unload();
    // FIXME release the rest!
  }
  
  public void init(ServletConfig config)
    throws ServletException {
    ais = (AgentIdentificationService)
      serviceBroker.getService(this, AgentIdentificationService.class, null);
    agentId = ais.getMessageAddress();
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

  private class CRLRegistrationViewerServlet extends HttpServlet {
    class CRLRegistrationPredicate implements UnaryPredicate {
      /** @return true if the object "passes" the predicate */
      public boolean execute(Object o) {
	boolean ret = false;
	if (o instanceof CrlRegistrationTable ) {
	  return true;
	}
	return ret;
      }
    }
    
    public void doGet(HttpServletRequest request,
		      HttpServletResponse response)
      throws IOException {
      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println("<title>CRL Registration Viewer </title>");
      out.println("</head>");
      out.println("<body>");
      out.println("<H2>CRL Registration Viewer</H2><BR>");
      out.println("<H3>CRL Registration at agent :"+ agentId.toAddress() +"</H3>");
      Collection registrationCollection=null;
      try {
	out.println("<H3> Query of the Blackboard started  :"+ agentId.toAddress() +"</H3>");
	out.flush();
	blackboard.openTransaction();
	registrationCollection=blackboard.query(new CRLRegistrationPredicate());
	out.println("<H3> Query of the Blackboard Completed   :"+ agentId.toAddress() +"</H3>");
	out.flush();
      }
      catch(Exception exp) {
	out.println("<H3> Exception has occured at  :"+ agentId.toAddress()+ "Messgae :"+ exp.getMessage() +"</H3>");
	out.flush();
      }
      finally {
	blackboard.closeTransaction();
      }
      if((registrationCollection==null)||registrationCollection.isEmpty()) {
	out.println("ERROR CRL Registration  Table is not present ");
	out.flush();
	out.close();
	return;
      }
      if( registrationCollection.size()>1) {
	logging.error("Multiple CRL Registration Table on the blackboard:"+agentId.toAddress());
	out.println("Multiple CRL Registration Table on the blackboard:"+agentId.toAddress());
	out.flush();
	out.close();
	return;
      }
      CrlRegistrationTable crlRegistrationTable=null;
      Iterator iter=registrationCollection.iterator();
      if(iter.hasNext()) {
        crlRegistrationTable=(CrlRegistrationTable)iter.next();
        
      }
       String result=null;
      if(crlRegistrationTable!=null) {
	result=createTable(crlRegistrationTable);
        out.println( result);
      }
      out.println("</body></html>");
      out.flush();
      out.close();
   

    }

    public String createTable(CrlRegistrationTable crlRegistrationTable) {
      StringBuffer sb=new StringBuffer();
      sb.append("<table align=\"center\" border=\"2\">\n");
      sb.append("<TR><TH> CA DN  </TH><TH> Registered Agent </TH><TH> Last Modified Time Stamp </TH></TR>\n");
      Enumeration keys=crlRegistrationTable.keys();
      String key=null;
      CrlRegistrationObject crlreg=null;
      Vector messageAddress=null;
      while(keys.hasMoreElements()) {
	key=(String)keys.nextElement();
	crlreg=(CrlRegistrationObject)crlRegistrationTable.get(key);
        sb.append("<TR><TD>\n");
	sb.append(crlreg.dnName);
	sb.append("&nbsp;&nbsp;</TD>\n");
        messageAddress=crlreg.getRegisteredAgents();
        sb.append("<TD>\n");
	if((messageAddress!=null) &&(!messageAddress.isEmpty())) {
          sb.append("<OL>");
          Object obj=null;
          for(int i = 0 ; i < messageAddress.size() ; i++) {
            obj=(Object)messageAddress.elementAt(i);
	    sb.append("<LI>"+ obj.toString() +"\n");
	  }
	  sb.append("</OL>\n");
        }
        else {
          sb.append("----");
        }
        sb.append("</TD>\n");
        sb.append("<TD>\n");
        String lastmodified=null;
        lastmodified=crlreg.getModifiedTimeStamp();
        if(lastmodified!=null) {
          sb.append(lastmodified);
        }
        else {
          sb.append(" Not yet initialized ");
        }
        sb.append("</TD>\n");
      }
      sb.append("</table>");
      return sb.toString();
    }
  }

}
