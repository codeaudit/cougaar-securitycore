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

package org.cougaar.core.security.test.crypto.crl.servlet;


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


public class RemoveCRLRegistration extends BaseServletComponent implements BlackboardClient  {

  public static String HEADER_WITH_SCRIPT = "<html>" +
  "<script language=\"javascript\">" +
  "function submitme(form)" +
  "{ form.submit()}</script>" +
  "</head>" +
  "<body>";
  private AgentIdentificationService ais;
  private MessageAddress agentId;
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
  public void setAgentIdentificationService(AgentIdentificationService ais) {
    this.ais=ais;
    if(ais!=null) {
      agentId = ais.getMessageAddress();
    }
  }

  public void setLoggingService(LoggingService ls) {
    this.logging=ls;
  }
  
  protected Servlet createServlet() {
    if(agentId==null) {
      ais = (AgentIdentificationService)
        serviceBroker.getService(this, AgentIdentificationService.class, null);
      if(ais!=null) {
        agentId = ais.getMessageAddress();
      }
    }
    return new RemoveCRLRegistrationServlet();
  }

  public void unload() {
    super.unload();
    // FIXME release the rest!
  }
  
  public void init(ServletConfig config)
    throws ServletException {
    ais = (AgentIdentificationService)
      serviceBroker.getService(this, AgentIdentificationService.class, null);
    if(ais!=null) {
      agentId = ais.getMessageAddress();
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

  private class RemoveCRLRegistrationServlet extends HttpServlet {
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

    public void doPost(HttpServletRequest request,
                       HttpServletResponse response)
      throws IOException {
      if (ais == null) {
	ais = (AgentIdentificationService)
	  serviceBroker.getService(this, AgentIdentificationService.class,
				   null);
	agentId = ais.getMessageAddress();
      }
      String cadn=null;
      String agentname=null;
      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      out.println(HEADER_WITH_SCRIPT);
      cadn=request.getParameter("cadnname");
      agentname=request.getParameter("agentname");
      out.println("<H2>CRL Registration Remover </H2><BR>");
      out.println("<H3>CRL Registration Remover at agent :"
		  + agentId.toAddress() +"</H3>");
      
      if((cadn==null)||(agentname==null)||(cadn=="")||(agentname=="")){
        out.println("<H3> Either cadn or agent name is null or empty :"
                    + agentId.toAddress() +"</H3>");
        out.flush();
        out.close();
      }
      Collection registrationCollection=null;
      try {
	out.println("<H3> Query of the Blackboard started  :"
		    + agentId.toAddress() +"</H3>");
	out.flush();
	blackboard.openTransaction();
	registrationCollection=blackboard.query(new CRLRegistrationPredicate());
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
      if((registrationCollection==null)||registrationCollection.isEmpty()) {
	out.println("ERROR CRL Registration  Table is not present ");
	out.flush();
	out.close();
	return;
      }
      if( registrationCollection.size()>1) {
	logging.error("Multiple CRL Registration Table on the blackboard:"
		      +agentId.toAddress());
	out.println("Multiple CRL Registration Table on the blackboard:"
		    +agentId.toAddress());
	out.flush();
	out.close();
	return;
      }
      out.println("ca dn : "+ cadn);
        out.println("agentname= : "+ agentname);
      CrlRegistrationTable crlRegistrationTable=null;
      CrlRegistrationObject regobject=null;
      Iterator iter=registrationCollection.iterator();
      if(iter.hasNext()) {
        crlRegistrationTable=(CrlRegistrationTable)iter.next();
      }
      Vector agents=null;
      boolean modified=false;
      synchronized(crlRegistrationTable) {
        if(crlRegistrationTable.containsKey(cadn)) {
          regobject=(CrlRegistrationObject)crlRegistrationTable.get(cadn);
          try {
            regobject.removeAgent(agentname);
            modified=true;
          }
          catch(CRLAgentRegistrationException crlAgentException){
            out.println(crlAgentException.getMessage());
            out.flush();
            out.close();
            return;
          }
           
        }
        else {
          out.println("Could not find CADN in  CRL Registration Table. CADN :"+ cadn + "  at Agent "
                      +agentId.toAddress());
          out.flush();
          out.close();
          return; 
        }
      }
      if(modified) {
        crlRegistrationTable.put(cadn,regobject);
        try {
          blackboard.openTransaction();
          blackboard.publishChange(crlRegistrationTable);
        }
        catch (Exception exp) {
          out.println("Could not Remove agent from CRL Registration Table. CADN :"+ cadn + " agent Name : "+ agentname +
                      " at Agent " +agentId.toAddress());
          out.flush();
          out.close();
        }
        finally {
          blackboard.closeTransaction();
          
        }
      }
      out.println("Sucessfully Remove agent from CRL Registration Table. CADN :"+ cadn + " agent Name : "+ agentname +
                  " at Agent " +agentId.toAddress());
      out.flush();
      out.close();
      
    }
    
    public void doGet(HttpServletRequest request,
		      HttpServletResponse response)
      throws IOException {

      if (ais == null) {
	ais = (AgentIdentificationService)
	  serviceBroker.getService(this, AgentIdentificationService.class,
				   null);
	agentId = ais.getMessageAddress();
      }

      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      out.println(HEADER_WITH_SCRIPT);
      out.println("<H2>CRL Registration Remover </H2><BR>");
      out.println("<H3>CRL Registration Remover at agent :"
		  + agentId.toAddress() +"</H3>");
      Collection registrationCollection=null;
      try {
	out.println("<H3> Query of the Blackboard started  :"
		    + agentId.toAddress() +"</H3>");
	out.flush();
	blackboard.openTransaction();
	registrationCollection=blackboard.query(new CRLRegistrationPredicate());
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
      if((registrationCollection==null)||registrationCollection.isEmpty()) {
	out.println("ERROR CRL Registration  Table is not present ");
	out.flush();
	out.close();
	return;
      }
      if( registrationCollection.size()>1) {
	logging.error("Multiple CRL Registration Table on the blackboard:"
		      +agentId.toAddress());
	out.println("Multiple CRL Registration Table on the blackboard:"
		    +agentId.toAddress());
	out.flush();
	out.close();
	return;
      }
      CrlRegistrationTable crlRegistrationTable=null;
      Iterator iter=registrationCollection.iterator();
      if(iter.hasNext()) {
        crlRegistrationTable=(CrlRegistrationTable)iter.next();
        
      }
      String uri = request.getRequestURI();
      out.println("Received uRI is :"+ uri);
      String result=null;
      if(crlRegistrationTable!=null) {
	result=createTable(crlRegistrationTable,uri);
        out.println( result);
      }
      out.println("</body></html>");
      out.flush();
      out.close();
   

    }

    public String createTable(CrlRegistrationTable crlRegistrationTable, String posturl) {
      StringBuffer sb=new StringBuffer();
      sb.append("<table align=\"center\" border=\"2\">\n");
      sb.append("<TR><TH> CA DN  </TH><TH> Registered Agent </TH><TH> Last Modified Time Stamp </TH></TR>\n");
      Enumeration keys=crlRegistrationTable.keys();
      String key=null;
      CrlRegistrationObject crlreg=null;
      Vector messageAddress=null;
      int counter=1;
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
	    sb.append("<LI>");
            sb.append("<form name=\"Agentlist"+counter+i+"\""+ " action=\"" + posturl+ "\" method=\"post\" onSubmit =\"submitme(this)\">");
            sb.append("<input type=\"hidden\" name=\"cadnname\" value=\""+crlreg.dnName +"\""+ ">");
            sb.append("<input type=\"hidden\" name=\"agentname\" value=\""+obj.toString()+"\""+ ">"); 
            sb.append(obj.toString() +"\n");
            sb.append("<input type=\"Submit\" value=\"Remove Registration \"></form>");
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
        counter++;
      }
      sb.append("</table>");
      return sb.toString();
    }
  }
}
