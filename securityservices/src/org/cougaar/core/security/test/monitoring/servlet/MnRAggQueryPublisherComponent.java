/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software Inc.
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

package org.cougaar.core.security.test.monitoring.servlet;

// Imported java classes
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.FormatEvent;
import org.cougaar.core.security.monitoring.blackboard.MnRAggRateCalculator;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.lib.aggagent.query.AggregationQuery;
import org.cougaar.lib.aggagent.query.ScriptSpec;
import org.cougaar.lib.aggagent.util.Enum.Language;
import org.cougaar.lib.aggagent.util.Enum.QueryType;
import org.cougaar.lib.aggagent.util.Enum.ScriptType;
import org.cougaar.lib.aggagent.util.Enum.UpdateMethod;
import org.cougaar.lib.aggagent.util.Enum.XmlFormat;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 *  Use the TraX interface to perform a transformation.
 */
public class MnRAggQueryPublisherComponent
extends BaseServletComponent implements BlackboardClient  {
  private MessageAddress agentId;
  private AgentIdentificationService ais;
  private BlackboardService blackboard;
  private DomainService ds;
  private CommunityService cs;
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

  public void setAgentIdentificationService(AgentIdentificationService ais) {
    this.ais = ais;
    if(this.ais!=null) {
      agentId = ais.getMessageAddress(); 
    }
  }

  public void setBlackboardService(BlackboardService blackboard) {
    this.blackboard = blackboard;
  }

  public void setDomainService(DomainService ds) {
    this.ds = ds;
  }
  
  public void setCommunityService(CommunityService cs) {
    //System.out.println(" set community services call for Servlet component :");
    this.cs=cs;
  }
  /*
    public void setNamingService(NamingService ns) {
    //System.out.println(" set  Naming services call for Servlet component :");
    this.ns=ns;
    }*/
  
  protected Servlet createServlet() {
    return new PublisherServlet();
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

  private class PublisherServlet extends HttpServlet {

      
    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
      throws IOException {
      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      StringBuffer buff= new StringBuffer();
      buff.append(CreateHeader());
      buff.append(CreatePage(request));
      buff.append(CreateTail());
      out.println(buff.toString());
      out.flush();
      out.close();
   

    }
    public void doPost(HttpServletRequest request,
                       HttpServletResponse response)
      throws IOException {
      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      boolean message=false;
      boolean query=false;
      String parameter=null;
      String mnrMgr=null;
      parameter =(String)request.getParameter("mnrMgr");
      out.println(CreateHeader());
      if(parameter!=null) {
        mnrMgr=(String)parameter;
      }
      if(mnrMgr==null) {
        out.println("<H2>MnR DRILL Down  Query publisher </H2><BR>");
        out.println("Target agent for query is NULL  :");
        out.println(CreateTail());
        out.flush();
        out.close();
        return;
      }
      CmrFactory factory=(CmrFactory)ds.getFactory("cmr");
      CmrRelay relay=null;
      // QueryResultAdapter qra = createQuery();
      AggregationQuery aquery = createQuery();//qra.getQuery();
      out.println(" Query spec is :"+ aquery.getPredicateSpec());
      // aquery.addSourceCluster("SecurityManager-1");
      try {
        blackboard.openTransaction();
        relay=factory.newDrillDownQueryRelay(aquery.toXml(),new MnRAggRateCalculator(120),false,
                                             MessageAddress.getMessageAddress(mnrMgr));
        out.println(" publishing relay to ---> " +mnrMgr );
        blackboard.publishAdd(relay);
        
      } finally {
        blackboard.closeTransactionDontReset();
      }        
           
      // PrintWriter out = response.getWriter();
      //String page=CreatePage(request);
      out.println("<H3> Successfully published Agg Query to Agent :"+mnrMgr +"<H3>" );
      out.println(CreateTail());
      out.flush();
      out.close();
    }
    
  }

  public String CreateHeader () {
    StringBuffer buf =new StringBuffer();
    buf.append("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    buf.append("<html>");
    buf.append("<head>");
    buf.append("<title>MnR Drill down Query Publisher </title>");
    buf.append("</head>");
    buf.append("<body>");
    return  buf.toString();
  }

  public String CreateTail () {
    StringBuffer buf =new StringBuffer();
    buf.append("</body>");
    buf.append("</html>");
    return  buf.toString();
  }

  public String  CreatePage( HttpServletRequest req) {
    StringBuffer buf =new StringBuffer();
    buf.append("<H2>MnR Drill down Query Publisher </H2><BR>");
    buf.append(" <br>  <br>  <br>");
     buf.append("<H3>Publish SecurityManagerException query to target MnR Manager  </H3><BR>");
    buf.append("<table>");
    buf.append("<form action=\"" + req.getRequestURI() + "\" method =\"post\">");
    buf.append("<TR>Target MnRManager &nbsp;&nbsp; :&nbsp; <input name=\"mnrMgr\"  value=\"\">");
    buf.append("</tr>");
    buf.append("<TR><input type=\"Submit\" value=\"Publish Agg Query \"> </TR>");
    buf.append("</form></table>");
    
    return buf.toString();
    
  }
  protected AggregationQuery createQuery() {

    String up="org.cougaar.core.security.monitoring.plugin.AllBootStrapFailures";
    ScriptSpec FORMAT_SPEC = new ScriptSpec(Language.JAVA, XmlFormat.INCREMENT, 
                                            FormatEvent.class.getName());
    ScriptSpec spec= new ScriptSpec(ScriptType.UNARY_PREDICATE, Language.JAVA, up);
    AggregationQuery aq = new AggregationQuery(QueryType.PERSISTENT);
    aq.setName("Event Query");
    aq.setUpdateMethod(UpdateMethod.PUSH);
    aq.setPredicateSpec(spec);
    aq.setFormatSpec(FORMAT_SPEC);
    return aq;
  }
  
 
}

