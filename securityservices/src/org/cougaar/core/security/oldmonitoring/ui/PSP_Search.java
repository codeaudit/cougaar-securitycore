/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates Technology, Inc.
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
 
 
package org.cougaar.core.security.oldmonitoring.ui;


import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.blackboard.*;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.glm.ldm.asset.Organization;
import org.cougaar.lib.planserver.*;
import org.cougaar.core.domain.RootFactory;
import java.io.*;
import java.util.*;
import org.cougaar.core.security.oldmonitoring.util.*;


class GetResponsePredicate implements UnaryPredicate
{
  public boolean execute(Object o)
  {
    return o instanceof ResponseObj;
  }
}


public class PSP_Search extends PSP_BaseAdapter implements PlanServiceProvider, UISubscriber
{
    
  /** Creates new PSP_Search */
  public PSP_Search()
  {
    super(); 
  }
  
  public PSP_Search( String pkg, String id ) throws RuntimePSPException
  {
    setResourceLocation(pkg, id);
  }
  
  public boolean test(HttpInput query_parameters, PlanServiceContext sc)
  {
    super.initializeTest(); // IF subclass off of PSP_BaseAdapter.java
    return false;  // This PSP is only accessed by direct reference.
  }
  public void execute( PrintStream out,HttpInput query_parameters,PlanServiceContext psc,PlanServiceUtilities psu ) throws Exception
  {
    try  {
      Vector url =query_parameters.getParameterTokens("ver",'=');;
      if(MonitoringUtils.debug>0)
	System.out.println("IN Search PSP cluster id  string is :"+psc.getServerPluginSupport().getClusterIDAsString());
      Vector vulnerablevector=null;
      if(url==null)   {
	out.println("<HTML><head>");
	out.println(insertJavascript(psc.getServerPluginSupport().getClusterIDAsString()));
	out.println("<body><h2> Search for Vulnerability</h2>");
	out.println("<form name=\"choiceForm\" Method=\"GET\" >");                
	out.println("<SELECT NAME=\"Vulnerability\" SIZE=\"1\">");
	out.println("<OPTION value=\"POD\">POD");
	out.println("<OPTION value=\"TCPSCAN\">TCPSCAN");
	out.println("<OPTION value=\"UDPSCAN\">UDPSCAN");
	out.println("<OPTION value=\"SecurityException\">SecurityException");
	
	out.println("</SELECT>");
	out.println("<input type=\"button\"  value=\"Submit\" onClick=\"javascript:submitMe()\" >");
	out.println("<INPUT TYPE=\"button\"  VALUE=\"Reset\"></FORM>");
	Vector allnames=new Vector();
	Vector alllinks=new Vector();
	psc.getAllURLsAndNames(alllinks,allnames);
	//psc.getAllNames(allnames);
	/*
	  for(int i=0;i<allnames.size();i++)
	  {
	  out.println("name at ::"+i+(String)allnames.elementAt(i)+"\n");
	  }
	  for(int i=0;i<alllinks.size();i++)
	  {
	  out.println("links ::"+i+(String)alllinks.elementAt(i)+"\n");
	  }*/
      }
      else  {
	long id=0;
	if(MonitoringUtils.debug>0)
	  System.out.println("Got verb  to look for");
	//psc.getServerPluginSupport().openLogPlanTransaction();
	for(int i=0; i<url.size();i++)   {
	  String type=(String) url.elementAt(i);
	  id=System.currentTimeMillis();
	  Query tempquery=new Query(type,id);
	  if(MonitoringUtils.debug>0)
	    System.out.println("Specified type Vernability in search PSP is  :"+type);
	  // Task tsk=  createsearchTask( psc.getServerPluginSupport().getFactoryForPSP(), MonitoringUtils.Query_PSP_Verb,type);
	  psc.getServerPluginSupport().publishAddForSubscriber(tempquery);
	  
	}
	
	boolean wait=true;
	Collection c= psc.getServerPluginSupport().queryForSubscriber(new GetResponsePredicate());
	boolean first=true;
	while(wait)   {
	  if(contains_id(c,id))   {
	    wait=false;
	    out.println("<html><head>");
	    out.println(insertJavascript_publish(psc.getServerPluginSupport().getClusterIDAsString()));
	    out.println("<body>");
	    Vector response=getResponseObj(c,id);
	    for(Iterator i=response.iterator();i.hasNext();)   {
	      ResponseObj obj=(ResponseObj)i.next();
	      out.println(process_Response(obj));
	      if(MonitoringUtils.debug>0)
		System.out.println("IN serch PSP response obj is  ::::::"+obj.toString());
	    }
	    out.println("</body></html>");
	    out.flush();
	    
	  }
	  else   {
	    c= psc.getServerPluginSupport().queryForSubscriber(new GetResponsePredicate());
	    if(first)  {
	      out.println("<html><body><h2>Please wait search in progress</h2></body></html>");
	      out.flush();
	      first=false;
	    }
	  }
	  
	}
      }
      out.println("</BODY></HTML>");
      out.flush();
      out.close();
      
    }
    catch (Exception ex)   {
      out.println(ex.getMessage());
      ex.printStackTrace(out);
      System.out.println(ex);
      out.flush();
      out.close();
    }
  }
  
  public boolean returnsXML() {
    return false;
  }
  
  public boolean returnsHTML() {
    return true;
  }
  
  /**
   * Any PlanServiceProvider must be able to provide DTD of its
   * output IF it is an XML PSP, ie  returnsXML() == true
   * or return null
   */
  public String getDTD()  {
    return null;
  }
  
  /**
   * The UISubscriber interface. (not needed)
   */
  public void subscriptionChanged(Subscription subscription)
  {
  }

  /**
     Inserts javascript code in the outgoing HTML
  **/
  public String insertJavascript(String clusterid)
  {
    StringBuffer js=new StringBuffer();
    js.append("<SCRIPT LANGUAGE=\"JavaScript\">");
    js.append("function submitMe() {\n");
    //js.append("alert(\"function submit me called\");");
    js.append("var strValues = \"ver=\";\n");
    js.append("var selected = document.choiceForm.Vulnerability.selectedIndex;\n");
    //js.append("alert(selected)\n");
    js.append("strValues = strValues+document.choiceForm.Vulnerability[selected].value;\n");
    js.append("document.choiceForm.action=\"/$" );
    js.append(  clusterid);
    js.append("/Search.PSP?\"\n");
    //js.append("alert( document.choiceForm.action +strValues);\n");
    js.append("document.location.href=document.choiceForm.action +strValues;\n");
    js.append(" }</script></head>");
    return js.toString();
  }

  private String process_Response(ResponseObj robj)
  {
    StringBuffer out=new StringBuffer();
    out.append("<fieldset><legend>MRCM----"+robj.Type+" Vulnerability Services Available At <br></legend>");
    if((robj.Sensors.size()<1)||(robj.Analyzers.size()<1))  {
      if(robj.Sensors.size()<1)  {
	out.append("<h2> No Sensor present for "+robj.Type+"</h2>");
      }
      else  {
	out.append("<h2> No Analyzer present for "+robj.Type+"</h2>");
      }
      out.append("<a href=\"/Search.PSP\">");
      // link to cluster
      out.append("Search </a> ");
      return out.toString();
    }
    
    out.append("<form name=\"selectForm\" Method=\"POST\" >");                
    out.append("<input type=\"hidden\"  name=\"type\" value="+robj.Type+">");
    out.append("<input type=\"hidden\"  name=\"uniqueid\" value="+robj.unique_id+">");
    out.append("<TABLE BORDER ALIGN=LEFT>");
    out.append("<TR><TH>Sensor Name </TH><TH>Analyzer Name </TH></TR>");
    out.append("<TR><td><SELECT NAME=\"Sensors\" SIZE=\"1\">");
    for(int i=0 ;i<robj.Sensors.size();i++ )   {
      String str= ((Organization)robj.Sensors.elementAt(i)).getClusterIdentifier().toAddress();   
      out.append("<OPTION value=\""+str +"\">"+str);
      
    }
    out.append("</select></td>");
    out.append("<td><SELECT NAME=\"Analyzers\" SIZE=\"1\">");
    for(int i=0 ;i<robj.Analyzers.size();i++ )   {
      String str= ((Organization)robj.Analyzers.elementAt(i)).getClusterIdentifier().toAddress();   
      out.append("<OPTION value=\""+str +"\">"+str);
      
    }
    out.append("</select></td></tr>");
    out.append("</table>");
    out.append("<input type=\"button\"  value=\"Submit\" onClick=\"javascript:PublishMe()\" >");
    out.append("<INPUT TYPE=\"button\"  VALUE=\"Reset\"></FORM>");
    
    return out.toString();
  }
  public String insertJavascript_publish(String clusterid)
  {
    StringBuffer js=new StringBuffer();
    js.append("<SCRIPT LANGUAGE=\"JavaScript\">");
    js.append("function PublishMe() {\n");
    //js.append("alert(\"function publishme me called\");");
    js.append("var selectedsensor = document.selectForm.Sensors.selectedIndex;\n");
    js.append("var selectedanalyzer = document.selectForm.Analyzers.selectedIndex;\n");
    //js.append("alert(selectedsensor + selectedanalyzer )\n");
    js.append("if(selectedsensor==-1){\n");
    js.append("alert(\" Select sensor\");return;}");
    js.append("if(selectedanalyzer==-1){\n");
    js.append("alert(\" Select analyzer\");return;}");
    js.append("document.selectForm.action=\"/$" );
    js.append(  clusterid);
    js.append("/Publish.PSP?\";\n");
    js.append("document.selectForm.submit();");
    js.append(" }</script></head>");
    return js.toString();
  }

  boolean contains_id(Collection response,long id)
  {
    boolean containsid=false;
    for(Iterator i=response.iterator();i.hasNext();)   {
      ResponseObj resobj=(ResponseObj)i.next();
      if(resobj.unique_id==id)  {
	containsid=true;
      }
    }
    return  containsid;
    
  }
  
  Vector getResponseObj(Collection response,long id)
  {
    Vector  responsevector=new Vector();
    for(Iterator i=response.iterator();i.hasNext();)   {
      ResponseObj resobj=(ResponseObj)i.next();
      if(resobj.unique_id==id)  {
	responsevector.add( resobj);
      }
    }
    return  responsevector;
    
  }
  
    
}
