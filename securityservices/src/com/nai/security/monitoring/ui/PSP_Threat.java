
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
 
 
package com.nai.security.monitoring.ui;

import java.io.*;
import java.util.*;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLEncoder;

import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.blackboard.*;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.lib.planserver.*;
import org.cougaar.core.domain.RootFactory;
import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;
import org.cougaar.lib.planserver.*;
import org.cougaar.glm.ldm.asset.Organization;

import com.nai.security.monitoring.util.*;


public class PSP_Threat extends PSP_BaseAdapter implements PlanServiceProvider, UISubscriber
{
   /** Creates new PSP_Search */
  class ThreatPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      if(o instanceof Task)  {
	Task task=(Task )o;
	return (task.getVerb().equals(MonitoringUtils.Sensor_Data));
      }
      return false;
    }
  }
  
  public PSP_Threat()
  {
    super(); 
  }
    
  public PSP_Threat( String pkg, String id ) throws RuntimePSPException
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
    MyPSPState myState = new MyPSPState(this, query_parameters, psc);
    myState.configure(query_parameters);
    
    try {
      switch (myState.mode) {
      default:
	System.err.println("DEFAULT MODE");
	display_allthreats(myState, out);
	break;
      case MyPSPState.MODE_ALL_TASK:
	display_allthreats(myState, out);
	break;
      case MyPSPState.MODE_TASK_DETAILS:
	display_details(myState,out);
	break;
      }
    } 
    catch (Exception e) {
      System.err.println("Threats.PSP Exception: ");
      System.err.println(e);
      e.printStackTrace();
      out.print( "<html><body><h1>"+"<font color=red>Unexpected Exception!</font>"+ "</h1><p><pre>");
      e.printStackTrace(out);
      out.print("</pre></body></html>");
      out.flush();
    }
    out.flush();
    out.close();
  }

  protected static UnaryPredicate getUniqueObjectWithUIDPred( final String uidFilter)
  {
    final UID findUID = UID.toUID(uidFilter);
    return new UnaryPredicate() {
	public boolean execute(Object o) {
	  if (o instanceof UniqueObject) {
	    UID u = ((UniqueObject)o).getUID();
	    return
	      findUID.equals(u);
	  }
	  return false;
	}
      };
  }

  protected static UniqueObject findUniqueObjectWithUID(
							MyPSPState myState, final String itemUID)
  {
    if (itemUID == null) {
      // missing UID
      return null;
    }
    Collection col =
      searchUsingPredicate(
			   myState,
			   getUniqueObjectWithUIDPred(itemUID));
    if (col.size() < 1) {
      // item not found
      return null;
    }
    // take first match
    Iterator iter = col.iterator();
    UniqueObject uo = (UniqueObject)iter.next();
    if (MonitoringUtils.debug> 0)  {
      if (iter.hasNext()) {
	System.err.println("Multiple matches for "+itemUID+"?");
      }
    }
    return uo;
  }

  protected static Collection searchUsingPredicate( MyPSPState myState, UnaryPredicate pred)
  {
    return myState.sps.queryForSubscriber(pred);
  }
  
  private void display_details(MyPSPState myState,PrintStream out)
  {
    out.print(
	      "<html>\n"+
	      "<head>\n"+
	      "<title>"+
	      "Threats Detailed View"+
	      "</title>"+
	      "</head>\n"+
	      "<body  bgcolor=\"#F0F0F0\">\n"+
	      "<b>");
    // link to cluster
    out.print(
	      "</b><br>\n"+
	      "Threat Details<br>");
    // find task
    UniqueObject baseObj = findUniqueObjectWithUID(myState, myState.itemUID);
    if (baseObj instanceof Task)   {
      printThreatDetails(myState, out, (Task)baseObj);
    } 
    else   {
      out.print("<p>"+"<font size=small color=mediumblue>");
      if (myState.itemUID == null)  {
	out.print("No Threat selected.");
      }
      else if (baseObj == null) {
	out.print("No Threat  matching \"");
	out.print(myState.itemUID);
	out.print("\" found.");
      } 
      else  {
	out.print("UniqueObject with UID \"");
	out.print(myState.itemUID);
	out.print("\" is not a Task: ");
	out.print(baseObj.getClass().getName());
      }
      out.print( "</font>"+ "<p>\n");
      
    }
    out.println("<p>");
    // link to cluster
    printLinkToTasksSummary(myState, out);
    out.print("</body>\n"+"</html>\n");
    out.flush();
      
  }
  private void printThreatDetails(MyPSPState myState, PrintStream out, Task task)
  {
    SensorDataObj sensor_data;
    out.print( "<ul>\n"+ "<li>"+ "<font size=medium color=mediumblue>UID= ");
    // show uid
    UID tu;
    String tuid;
    if (((tu = task.getUID()) != null) && ((tuid = tu.toString()) != null))  {
      out.print(tuid);
    } 
    else  {
      out.print("</font><font color=red>missing</font>");
    }
    PrepositionalPhrase pp=task.getPrepositionalPhrase(MonitoringUtils.Send_SensorData_Preposition);
    if(pp!=null)   {
      sensor_data=(SensorDataObj)pp.getIndirectObject();
      out.print( "</font>"+  "</li>\n"+  "<li>"+"<font size=medium color=mediumblue>Type of Threat= ");
      out.print(sensor_data.type);
      out.print( "</font>"+  "</li>\n"+  "<li>"+"<font size=medium color=mediumblue>Time = ");
      out.print(sensor_data.time.toString());
      out.print( "</font>"+  "</li>\n"+  "<li>"+"<font size=medium color=mediumblue>Node Source = ");
      out.print(sensor_data.Nodename);
      out.print( "</font>"+  "</li>\n"+  "<li>"+"<font size=medium color=mediumblue>Agent  Source = ");
      out.print(task.getSource().getAddress());
      out.print( "</font>"+  "</li>\n"+  "<li>"+"<font size=medium color=mediumblue>Data = ");
      out.print(sensor_data.data);
      out.print( "</font>"+  "</li>\n");
    }
    else  {
      out.print("</font><font color=red>Wrong Data format </font>");
    }
      
  }
  
  private void display_allthreats(MyPSPState mystate,PrintStream out)
  {
    out.println("<html>");
    out.println("<body>");
    Collection c= searchUsingPredicate(mystate,new ThreatPredicate());
    Task task;
    SensorDataObj sensor_data;
    Hashtable sorted=null;	
    if(!c.isEmpty())  {
      sorted=process_task(c);
      
    }
    if((!c.isEmpty())&&(sorted!=null))  {
      out.println("<h3>Possible Threats detected  at cluster "+mystate.sps.getClusterIDAsString()+"</h3>");
      Enumeration keys=sorted.keys();
      for(;keys.hasMoreElements();)  {
	String Key=(String)keys.nextElement();
	out.println("<h3> Threat :"+Key +"</h3>"); 	
	out.println("<table BORDER=\"3\"  CELLSPACING=\"4\" >");
	out.println("<tr><th>Type</th><th>Time</th><th>From Node </th><th>From Agent </th><th>Data</td>");
	Vector sensordata=(Vector)sorted.get(Key);
	for(int i=0;i<sensordata.size();i++)   {
	  task=(Task)sensordata.elementAt(i);
	  PrepositionalPhrase pp=task.getPrepositionalPhrase(MonitoringUtils.Send_SensorData_Preposition);
	  if(pp!=null)   {
	    sensor_data=(SensorDataObj)pp.getIndirectObject();
	    out.print("<tr><td>");
	    printLinkToLocalTask(mystate,out,task,sensor_data.type);
	    out.print("</td><td>"+sensor_data.time+"</td><td>"+sensor_data.Nodename+"</td><td>"+task.getSource().getAddress()+"</td><td>");
	    if(sensor_data.data.length()>50)   {
	      out.print("<pre>"+sensor_data.data.substring(0,50)+"....</pre></td></tr>");
	    }
	    else
	      out.print("<pre>"+sensor_data.data+"</pre></td></tr>");
	    out.print("\n");
	  }
	}
	out.println("</table>");
      }
    }
    else  {
      out.println("<h2> No threats detected at cluster "+mystate.sps.getClusterIDAsString()+"</h2>");
    }
    
    out.println("</body></html>");
    out.flush();
    
  }
  
  private Hashtable process_task(Collection alltask)
  {
    Hashtable tasklist=new Hashtable();
    Task tsk;
    SensorDataObj sensordata;
    for(Iterator i=alltask.iterator();i.hasNext();)  {
      tsk=(Task)i.next();
      PrepositionalPhrase pp=tsk.getPrepositionalPhrase(MonitoringUtils.Send_SensorData_Preposition);
      if(pp!=null)  {
	sensordata=(SensorDataObj)pp.getIndirectObject();
	if(tasklist.containsKey(sensordata.type)) {
	  Vector tasks=(Vector)tasklist.get(sensordata.type);
	  tasks.add(tsk);
	  tasklist.put(sensordata.type,tasks);
	}
	else  {
	  Vector tasks=new Vector();
	  tasks.add(tsk);
	  tasklist.put(sensordata.type,tasks);
	}
      }
    }
    return tasklist;
  }
  
  /**
   * print link to task summary at this cluster.
   */
  protected static void printLinkToTasksSummary(MyPSPState myState, PrintStream out)
  {
    printLinkToTasksSummary( myState, out, myState.clusterID, myState.encodedClusterID);
  }
  
  /**
   * print link to task summary for given cluster
   *
   * @param encodedClusterID the result of encode(clusterID)
   */
  protected static void printLinkToTasksSummary(MyPSPState myState, PrintStream out,String clusterID, String encodedClusterID)
  {
    if (clusterID != null) {
      out.print("<a href=\"/$");
      // link to cluster
      out.print(encodedClusterID);
      out.print(myState.psp_path);
      out.print(
		"?"+
		MyPSPState.MODE+
		"="+
		MyPSPState.MODE_ALL_TASK);
      out.print("\" >");
      out.print(clusterID);
      out.print(
		"</a>");
    } else {
      out.print("<font color=red>Unknown cluster</font>");
    }
  }
  
  
  protected static void printLinkToLocalTask( MyPSPState myState, PrintStream out, Task task,String linkdata)
  {
    printLinkToTask( myState, out, task,myState.clusterID, myState.encodedClusterID,linkdata);
  }
  
  protected static void printLinkToTask(MyPSPState myState, PrintStream out,Task task,String atCluster, String atEncodedCluster,String linkdata)
  {
    UID taskU;
    String taskUID;
    if (task == null)   {
      out.print("<font color=red>null</font>");
    } 
    else if (((taskU = task.getUID()) == null) || ((taskUID = taskU.toString()) == null))   {
      out.print("<font color=red>not unique</font>");
    } 
    else    {
      out.print("<a href=\"/$");
      out.print(atEncodedCluster);
      out.print(myState.psp_path);
      out.print( "?"+MyPSPState.MODE+"="+MyPSPState.MODE_TASK_DETAILS+"?"+MyPSPState.ITEM_UID+ "=");
      out.print(encode(taskUID)+"\">");
      out.print(linkdata);
      out.print("</a>");
    }
  }
  /**
   * bit[] based upon URLEncoder.
   */
  static boolean[] DONT_NEED_ENCODING;
  static {
    DONT_NEED_ENCODING = new boolean[256];
    for (int i = 'a'; i <= 'z'; i++) {
      DONT_NEED_ENCODING[i] = true;
    }
    for (int i = 'A'; i <= 'Z'; i++) {
      DONT_NEED_ENCODING[i] = true;
    }
    for (int i = '0'; i <= '9'; i++) {
      DONT_NEED_ENCODING[i] = true;
    }
    DONT_NEED_ENCODING['-'] = true;
    DONT_NEED_ENCODING['_'] = true;
    DONT_NEED_ENCODING['.'] = true;
    DONT_NEED_ENCODING['*'] = true;
  }
  
  /**
   * URL-encoding for strings that typically don't require encoding.
   *
   * Saves some String allocations.
   */
  protected static final String encode(String s) {
    int n = s.length();
    for (int i = 0; i < n; i++) {
      int c = (int)s.charAt(i);
      if (!(DONT_NEED_ENCODING[i])) {
        return URLEncoder.encode(s);
      }
    }
    return s;
  }
  
  public boolean returnsXML() {
    return false;
  }
  
  public boolean returnsHTML() {
    return true;
  }
  
  /**  Any PlanServiceProvider must be able to provide DTD of its
   *  output IFF it is an XML PSP... ie.  returnsXML() == true;
   *  or return null
   **/
  public String getDTD()  {
    return null;
   }
  
  /**
   * The UISubscriber interface. (not needed)
   */
   public void subscriptionChanged(Subscription subscription)
  {
    
  } 
  protected static class MyPSPState extends PSPState 
  {
    String itemUID;
    int mode;
    public static final String MODE = "mode";
    public static final String ITEM_UID = "uid";
    public static final int MODE_ALL_TASK                 =  0;
    public static final int MODE_TASK_DETAILS                 =  1;
    
    
    
    public MyPSPState(UISubscriber xsubscriber,HttpInput query_parameters, PlanServiceContext xpsc) 
    {
      super(xsubscriber, query_parameters, xpsc);
      mode=0;
    }
    public void setParam(String name, String value) 
    {
      if (name.equalsIgnoreCase(MODE))  {
	try  {
	  mode = Integer.parseInt(value);
	} 
	catch (Exception eBadNumber)  {
	  System.err.println("INVALID MODE: "+name);
	  mode =-1 ;
	}
      }
      else if (name.equalsIgnoreCase(ITEM_UID))  {
	if (value != null)  {
	  itemUID = URLDecoder.decode(value);
	}
      }
    }
  }
}

