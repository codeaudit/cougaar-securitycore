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


package org.cougaar.core.security.crypto.crl.servlet;

// Imported java classes
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.crypto.crl.blackboard.CrlRegistrationObject;
import org.cougaar.core.security.crypto.crl.blackboard.CrlRegistrationTable;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.util.UnaryPredicate;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;



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
  public void setAgentIdentificationService(AgentIdentificationService ais) {
    this.ais=ais;
    if(ais!=null) {
       agentId = ais.getMessageAddress();
    }
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
    if(agentId==null) {
      ais = (AgentIdentificationService)
        serviceBroker.getService(this, AgentIdentificationService.class, null);
      if(ais!=null) {
        agentId = ais.getMessageAddress();
      }
    }
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

      if (ais == null) {
	ais = (AgentIdentificationService)
	  serviceBroker.getService(this, AgentIdentificationService.class,
				   null);
	agentId = ais.getMessageAddress();
      }

      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println("<title>CRL Registration Viewer </title>");
      out.println("</head>");
      out.println("<body>");
      out.println("<H2>CRL Registration Viewer</H2><BR>");
      out.println("<H3>CRL Registration at agent :"
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
