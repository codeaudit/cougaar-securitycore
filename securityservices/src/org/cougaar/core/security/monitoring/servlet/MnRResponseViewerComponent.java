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

package org.cougaar.core.security.monitoring.servlet;

// Imported java classes
import java.io.*;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.ListIterator;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.naming.*;
import javax.naming.directory.*;
// IDMEF
import edu.jhuapl.idmef.*;

// Cougaar core services

import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.component.*;
import org.cougaar.core.service.*;
import org.cougaar.core.service.community.*;
import org.cougaar.core.servlet.BaseServletComponent;

import org.cougaar.core.domain.RootFactory;
import org.cougaar.core.servlet.SimpleServletSupport;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.util.*;
import org.cougaar.core.util.UID;

// Cougaar security services
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;


/**
 *  Use the TraX interface to perform a transformation.
 */
public class MnRResponseViewerComponent
  extends BaseServletComponent implements BlackboardClient  {
  private ClusterIdentifier agentId;
  private BlackboardService blackboard;
  private DomainService ds;
  private CommunityService cs;
  private NamingService ns;
  private RootFactory rootFactory;
  private LoggingService logging;
  private String path;

  public void load() {
    // FIXME need AgentIdentificationService
    org.cougaar.core.plugin.PluginBindingSite pbs =
      (org.cougaar.core.plugin.PluginBindingSite) bindingSite;
    this.agentId = pbs.getAgentIdentifier();
    
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
    this.rootFactory = ds.getFactory();
  }
  
   public void setCommunityService(CommunityService cs) {
     System.out.println(" set community services call for Servlet component :");
     this.cs=cs;
   }
  public void setNamingService(NamingService ns) {
     System.out.println(" set  Naming services call for Servlet component :");
     this.ns=ns;
  }
  public void setLoggingService(LoggingService ls) {
    this.logging=ls;
  }
  
  protected Servlet createServlet() {
    return new QueryResponseViewerServlet();
  }

  public void unload() {
    super.unload();
    // FIXME release the rest!
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

  private class QueryResponseViewerServlet extends HttpServlet {
   
    class QueryRespondRelayPredicate implements  UnaryPredicate{
      public boolean execute(Object o) {
	boolean ret = false;
	if (o instanceof CmrRelay ) {
	  CmrRelay relay = (CmrRelay)o;
	  ret =( relay.getContent() instanceof MRAgentLookUp );
	}
	return ret;
      }
    }
    
    class QueryMappingObjectPredicate implements UnaryPredicate{
      public boolean execute(Object o) {
	boolean ret = false;
	if (o instanceof  QueryMapping ) {
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
      out.println("<title>MnRQuery Response  Viewer </title>");
      out.println("</head>");
      out.println("<body>");
      out.println("<H2>MnRRegistration Viewer</H2><BR>");
      out.println("<H3> Monitoring and Response Query and Response  :"+ agentId.toAddress() +"</H3>");
      Collection querresponsecollection=null;
      Collection querymapping=null;
      try {
	blackboard.openTransaction();
	querresponsecollection=blackboard.query(new QueryRespondRelayPredicate());
	querymapping=blackboard.query(new QueryMappingObjectPredicate());
      }
      finally {
	blackboard.closeTransactionDontReset();
      }
      if((querresponsecollection==null)||querresponsecollection.isEmpty()) {
	out.println("No Query are currently present ");
	out.flush();
	out.close();
	return;
      }
      Iterator iter=querresponsecollection.iterator();
      CmrRelay relay=null;
      MRAgentLookUpReply reply=null;
      MRAgentLookUp query=null;
      StringBuffer sb=new StringBuffer();
      sb.append("<table align=\"center\" border=\"2\">\n");
      sb.append("<TR><TH> Relay ID  </TH><TH> Source </TH><TH>TARGET </TH><TH>IS Originator</TH><TH>SubQuery status </TH><TH>QUERY </TH><TH> Response </TH></TR>\n");
      while(iter.hasNext()) {
	relay = (CmrRelay)iter.next();
	sb.append("<TR><TD>\n");
	UID uid=relay.getUID();
	sb.append(uid.toString());
	sb.append("</TD>\n");
	sb.append("<TD>\n");
	if(relay.getSource()!=null) {
	  sb.append(relay.getSource().getAddress());
	}
	else {
	   sb.append(" unknown");
	}
	sb.append("</TD>\n");
	sb.append("<TD>\n");
	if(relay.getTarget()!=null) {
	  sb.append(relay.getTarget().getAddress());
	}
	else {
	  sb.append(" unknown");
	}
	sb.append("</TD>\n");
	sb.append("<TD>\n");
	QueryMapping mapping=findQueryMappingFromBB(uid,querymapping);
	boolean isorginator=isRelayQueryOriginator(uid,querymapping);
	if(isorginator) {
	  sb.append(true);
	}
	else {
	  sb.append(false);
	}
	sb.append("</TD>\n");
	sb.append("<TD>\n");
	if(isorginator) {
	  if(mapping!=null) {
	    ArrayList list=(ArrayList)mapping.getQueryList(); 
	    OutStandingQuery outstandingquery;
	    boolean modified=false;
	    if(list!=null) {
	      sb.append("<ol>"); 
	      for(int i=0;i<list.size();i++) {
		outstandingquery=(OutStandingQuery)list.get(i);
		sb.append("<li>Sub Query id and Status :"+ outstandingquery.toString()+"</li>\n");
	      }
	      sb.append("</ol>"); 
	    }
	  }
	}
	else {
	  sb.append("---");
	}
	sb.append("</TD>\n");
	sb.append("<TD>\n");
	if(relay.getContent()!=null){
	  query=(MRAgentLookUp)relay.getContent();
	  sb.append(query.toString());
	  // sb.append("</TD>\n"); 
	}
	sb.append("</TD>\n");
	sb.append("<TD>\n");
	if(relay.getResponse()!=null){
	  reply=(MRAgentLookUpReply)relay.getResponse();
	  List list=reply.getAgentList();
	  if(list!=null) {
	    if(!list.isEmpty()) {
	      sb.append("<ol>");
	      ListIterator iter1=list.listIterator();
	      ClusterIdentifier agentid=null;
	      while(iter1.hasNext()) {
		agentid=(ClusterIdentifier)iter1.next();
		sb.append("<li> "+ agentid.toString()+"</li>\n");
	      }
	      sb.append("</ol>"); 
	    }
	  }
	}
	sb.append("</TD>\n");
      }
      sb.append("</table>");
      out.println(sb.toString());
      out.println("</body></html>");
      out.flush();
      out.close();
   
    }
   
    public QueryMapping findQueryMappingFromBB(UID givenUID, Collection queryMappingCol ) {
    QueryMapping foundqMapping=null;
    ArrayList relayList;
    OutStandingQuery outstandingq;  
    //QueryMapping tempqMapping;
    if(!queryMappingCol.isEmpty()){
      if (logging.isDebugEnabled()) {
	logging.debug("Going to find uid from list of Query mapping Objects on bb in Response servlet "+queryMappingCol.size()); 
      }
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
	foundqMapping=(QueryMapping)iter.next();
	if(foundqMapping.getRelayUID().equals(givenUID)) {
	  return foundqMapping;
	}
	relayList=foundqMapping.getQueryList();
	if(relayList==null) {
	  return null;
	}
	for(int i=0;i<relayList.size();i++) {
	  outstandingq=(OutStandingQuery)relayList.get(i);
	  if(outstandingq.getUID().equals(givenUID)) {
	    if (logging.isDebugEnabled()) {
	      logging.debug(" Found given uid :"+ givenUID +" in object with UID :"+outstandingq.getUID());
	    }
	    return foundqMapping;
	  }
	}
      }
      
    }
    else {
      return null;
    }
    
    return null;
    }
    public boolean isRelayQueryOriginator(UID givenUID, Collection queryMappingCol ) {
      boolean isoriginator=false;
      QueryMapping querymapping=null;
      if(!queryMappingCol.isEmpty()){
	if (logging.isDebugEnabled()) {
	  logging.debug("Going to find if this relay id is originator of query in Response viewer servlet  :"); 
      }
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
	querymapping=(QueryMapping)iter.next();
	if(querymapping.getRelayUID().equals(givenUID)) {
	  isoriginator=true;
	  return isoriginator;
	}
      }
    }
    return isoriginator;
  }
    
  }

}
