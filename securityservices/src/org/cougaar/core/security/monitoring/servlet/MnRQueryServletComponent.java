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

package org.cougaar.core.security.monitoring.servlet;

// Imported java classes
import java.io.*;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.naming.*;
import javax.naming.directory.*;
// IDMEF
import edu.jhuapl.idmef.*;

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
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;


/**
 *  Use the TraX interface to perform a transformation.
 */
public class MnRQueryServletComponent
  extends BaseServletComponent implements BlackboardClient  {
  private MessageAddress agentId;
  private AgentIdentificationService ais;
  private BlackboardService blackboard;
  private DomainService ds;
  private CommunityService cs;
  private NamingService ns;
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
    agentId = ais.getMessageAddress(); 
  }

   public void setBlackboardService(BlackboardService blackboard) {
    this.blackboard = blackboard;
  }

  public void setDomainService(DomainService ds) {
    this.ds = ds;
  }
  
   public void setCommunityService(CommunityService cs) {
     System.out.println(" set community services call for Servlet component :");
     this.cs=cs;
   }
  public void setNamingService(NamingService ns) {
     System.out.println(" set  Naming services call for Servlet component :");
     this.ns=ns;
  }
  
  protected Servlet createServlet() {
    return new QueryServlet();
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

  private class QueryServlet extends HttpServlet {
    class QueryEventPredicate implements UnaryPredicate {
      /** @return true if the object "passes" the predicate */
      public boolean execute(Object o) {
	boolean ret=false; 
	if (o instanceof CmrRelay)  {
	  CmrRelay relay= (CmrRelay)o;
	  ret = (relay.getContent() instanceof MRAgentLookUp );
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
    out.println("<title>MnRQuery</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>MnRQuery </H2><BR>");
    out.println("<table>");
    out.println("<form action=\"query\" method =\"post\">");
    out.println("<tr ><td>Community </td><td>");
    out.println("<TextArea name=community row=1 col=40></TextArea></td></tr>");
    out.println("<tr ><td>Role </td><td>");
    out.println("<TextArea name=role row=1 col=40></TextArea></td></tr>");
    out.println("<tr ><td>ClassificationName </td><td>");
    out.println("<TextArea name=classificationName row=1 col=40></TextArea></td></tr>");
    out.println("<tr></tr><tr><td><input type=\"submit\">&nbsp;&nbsp;&nbsp;</td>");
    out.println("<td><input type=\"reset\"></td></tr>");
    out.println("</form></table>");
    out.println("</body></html>");
    out.flush();
    out.close();
   

  }
   public void doPost(HttpServletRequest request,
		    HttpServletResponse response)
    throws IOException {
     response.setContentType("text/html");
     PrintWriter out = response.getWriter();
     String classname=null;
     String role=null;
     String community=null;
     classname =(String)request.getParameter("classificationName");
     role=(String)request.getParameter("role");
     community=(String)request.getParameter("community");
     if((classname==null)&&(role==null)&&(community==null)){
       out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
       out.println("<html>");
       out.println("<head>");
       out.println("<title>MnRQuery</title>");
       out.println("</head>");
       out.println("<body>");
       out.println("<H2>MnRQuery </H2><BR>");
       out.println(" No Classification name  role  community specified :");
       out.println("</body></html>");
       out.flush();
       out.close();
      return;
     }
     out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
     out.println("<html>");
     out.println("<head>");
     out.println("<title>MnRQuery</title>");
     out.println("</head>");
     out.println("<body>");
     out.println("<H2>MnRQuery </H2><BR>");
     out.println(" checking whether community exists :<br>");
     
     CmrFactory factory=(CmrFactory)ds.getFactory("cmr");
     IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
     Classification classification=imessage.createClassification(classname, null );
     MRAgentLookUp agentlookup=new  MRAgentLookUp(null,null,null,null,classification,null,null);
     if((community!=null)&& (community!="")) {
       System.out.println(" setting community to :"+community); 
       agentlookup.community=community;
       
     }
     if((role!=null)) {
       if(role.equals("")) {
	 
       }
       else {
	 System.out.println("setting role to :"+role);
	 agentlookup.role=role;
       }
       
     }
     
     
     MessageAddress dest_address=MessageAddress.getMessageAddress("SocietySecurityManager");
     CmrRelay relay = factory.newCmrRelay(agentlookup,dest_address);
     try {
       blackboard.openTransaction();
       blackboard.publishAdd(relay);

     } finally {
       blackboard.closeTransactionDontReset();
     }
     boolean atleastone=false;
     out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
     out.println("<html>");
     out.println("<head>");
     out.println("<title>MnRQuery</title>");
     out.println("</head>");
     out.println("<body>");
     out.println("<H2>MnRQuery </H2><BR>");
      boolean printed=false;
     while(!atleastone) {
       Collection responsecol=blackboard.query(new QueryEventPredicate());
       Iterator it = responsecol.iterator();
       MRAgentLookUpReply  reply;
      
       CmrRelay previous=null;
       while(it.hasNext()) {
	 relay=(CmrRelay)it.next();
	 agentlookup=(MRAgentLookUp)relay.getContent() ;
	 if((relay.getSource().equals(agentId)) && (relay.getResponse()!=null)) {
	   atleastone=true;
	   out.println(" Query was" +agentlookup.toString());
	   out.println(" Response is  :");
	   reply=(MRAgentLookUpReply )relay.getResponse();
	   out.println(reply.toString());
	 }
	 else {
	   //out.println("relay receive was :"+relay.toString());
	 }
       }
     }
     out.flush();
     out.close();
         
   }
  }
  /*
  public void dummy() {    
    
    
    // boolean exists=cs.communityExists(classname);
    // out.println(" checking whether community :"+ classname +"  exists  :"+exists +" <br>");
    // System.out.println(" checking whether community :"+ classname +"  exists  :"+exists  +" <br>");
    // out.println(" Going to get all communities :" +" <br>"  );
    // System.out.println(" Going to get all communities :" +" <br>");
    
     Collection communities =cs.listAllCommunities();
     CommunityRoster roster;
     Iterator iter=communities.iterator();
     String community;
     while(iter.hasNext()) {
       out.println("-------------------------------------------------------------------------------<br>");
       community=(String)iter.next();
       out.println(" Got community name as :"+ community +" <br>");
      out.println(" Going to get attributes for community :"+ community +" <br>");
       Attributes atts=cs.getCommunityAttributes(community);
       NamingEnumeration natts=atts.getAll();
       Attribute att;
       try {
	 while(natts.hasMore()) {
	   att=(Attribute)natts.next();
	   out.println(" attribute ID ---------------->"+ att.getID()+ "<br>");
	   NamingEnumeration attval=att.getAll();
	   Object attvalue;
	   out.println(" going to print values for attribute with id---------------------------->"+att.getID()+ "<br>" ); 
	   while(attval.hasMore()){
	     attvalue=attval.next();
	     out.println("value for att ============> :"+attvalue+ "<br>" ); 
	   }
	 }
       }
       catch (Exception exp) {
	 exp.printStackTrace();
	 out.println(" exception occured :"+ exp.getMessage() + "<br>");
	 out.flush();
	 out.close();
       }
       
       // out.println(" Getting agents from community ------------->:"+ community +" <br>");
       //      roster=cs.getRoster(community);
       //Collection agents=roster.getMemberAgents();
       //out.println("going to display agents from community :++++++++++++++++++++++++++++++++++"+ community +" <br>");
       //Iterator agentiter=agents.iterator();
       //MessageAddress agent;
       // while(agentiter.hasNext()) {
       //agent=(MessageAddress)agentiter.next();
       //out.println(" Agent name:"+agent.toString() + " Community name  : "+ community +" <br>");
	 // System.out.println(" Agent name:"+ agent + " Community name  : "+ community);
       //}
       //out.println(" going to get member communities +++++++++++++++++++++++++++ <br>");
       //Collection  commember=roster.getMemberCommunities();
       //Iterator itercommember=commember.iterator();
       //String comm;
       //while(itercommember.hasNext()) {
       //comm=(String)itercommember.next();
       // out.println(" member community name:"+ comm +" <br>"  );
	 // System.out.println(" memeber community name:"+ comm  +" <br>");
       //}
       
       out.println(" Going to get community with community Type Security =============================<br>");
       String filter="(CommunityType=" + CommunityServiceUtil.SECURITY_COMMUNITY_TYPE + ")";
       Collection parent=cs.search(filter);
       Iterator itercommember=parent.iterator();
        String comm;
       out.println(" List of t communities is as follows --------------------------------->>>>>>>>>>>:<br>");
       while(itercommember.hasNext()) {
	 comm=(String)itercommember.next();
       	 out.println("community name with communityType attribute security :"+ comm +" <br>"  );
	 // System.out.println(" memeber community name:"+ comm  +" <br>");
	 out.println("Going to Perform search with filter value  community "+ comm +" role society: <br>"  );
//         filter="(Role=SecurityMnRManager-Society)";
	 Collection searchresult=cs.searchByRole(comm,"SecurityMnRManager-Society");
	 Iterator jiter=searchresult.iterator();
	 out.println("Result of search  is as follows --------------------------------->>>>>>>>>>>:");
	 while(jiter.hasNext()) {
	   comm=(String)jiter.next();
	   out.println("Perform search and result :"+ comm +" <br>"  );
	   // System.out.println(" memeber community name:"+ comm  +" <br>");
	 }	
       }
	
     }
     
     out.println(" Performing search on Naming service :<br>");
     String myfilter="(Role=SecurityMnRManager-Society)";
     //NamingService ns=(NamingService)cs.getNamingService(); 
     try {
       DirContext context= ns.getRootContext();
       SearchControls ctls = new SearchControls();
       ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
       NamingEnumeration ne= context.search("",myfilter,ctls);
       while(ne.hasMore()) {
	 SearchResult  result=(SearchResult)ne.next();
	 out.println("Result is :"+ result.getObject().toString());
       }
     }
     catch (Exception exp) {
       exp.printStackTrace();
       out.println(" Error in doing search :"+ exp.getMessage());
     }
     
     out.flush();
     out.close();



  }
  */

}

