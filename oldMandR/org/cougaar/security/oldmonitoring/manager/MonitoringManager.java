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

package org.cougaar.core.security.oldmonitoring.manager;

import java.util.Hashtable;
import java.util.Enumeration;
import java.util.Vector;
import java.util.Iterator;
import java.util.Collection;
import java.util.HashSet;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.domain.RootFactory;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.glm.ldm.asset.*;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.core.plugin.SimplePlugin;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.TimeSpan;
import org.cougaar.core.plugin.util.PluginHelper;

import org.cougaar.core.security.oldmonitoring.util.*;


/**
 * Monitoring Manager is responsible for managing all it subordinates,create 
 * a list of capabilities including f its own capabilities and of it subordinate
 * and publish it,talks to other managers and respond to queries it has received,
 * Sends command to sensor to start publishing.
 */

public class MonitoringManager extends SimplePlugin
{

  private IncrementalSubscription allCapabilitiesTask,allorganization,allcmdTask,allfindingtask;
  private Hashtable LocalYP_sensor;
  private Hashtable LocalYP_analyzer;
  
  Organization _self=null;
  boolean first=true;
  
  
  /**
   * A predicate that matches all "PROCESS_CAPABILITIES" tasks
   */
  class capabilitiesPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      if(o instanceof Task)  {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.PROCESS_CAPABILITIES_Verb));
      }
      return false;
    }
  }
  
  /**
   * A predicate that matches all "Finding_Sensor" tasks
   */
  class FindingSensorPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      if(o instanceof Task)  {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.Finding_Sensor_Verb));
      }
      return false;
    }
  }
  
  /**
   * A predicate that matches all Organization related to the cluster either through 
   * supporting /subordinate relationship.
   */
  class OrganizationPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      return( o instanceof Organization) ;
    }
  }
  
  /**
   *   A predicate that matches all "Start_Publishing_ui" task
   */
  class CmdTaskPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      if(o instanceof Task)  {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.Cmd_Interface_Verb));
      }
      return false;            
    }
  }
  
  /** Called during initialization to set up subscriptions.
   * More precisely, called in the plugin's Thread of execution
   * inside of a transaction before execute will ever be called.
   **/
  
  protected void setupSubscriptions()
  {
    allCapabilitiesTask=( IncrementalSubscription)subscribe(new capabilitiesPredicate());
    allorganization=(IncrementalSubscription)subscribe(new OrganizationPredicate());
    allcmdTask=(IncrementalSubscription)subscribe(new CmdTaskPredicate());
    allfindingtask=(IncrementalSubscription)subscribe(new FindingSensorPredicate());
    LocalYP_sensor=new Hashtable();
    LocalYP_analyzer=new Hashtable();
    
  }
  
  /**
   * Called inside of an open transaction whenever the plugin was
   * explicitly told to run or when there are changes to any of
   * our subscriptions.
   **/
  
  protected  void execute()
  {
    if(_self==null)   {
      _self=findself()  ;
    }
    Enumeration ecapTask=   allCapabilitiesTask.getAddedList();
    processCapabilitiesTask(ecapTask);
    Enumeration CmdTasklist=   allcmdTask.getAddedList();
    process_cmdTask(CmdTasklist);
    process_findingsensor(allfindingtask.getAddedList());
    //findsubordinateRoles(_self);
  }
  
  
  /**
   * Called when new "PROCESS_CAPABILITIES" tasks is added to the blackboard.In function each 
   * each new tasks indirect object is passed to processCapabilites function
   *
   * 
   * @param captask Enumeration on collection of "PROCESS_CAPABILITIES" tasks
   */
  private void  processCapabilitiesTask(Enumeration captask)
  {
    boolean newcapab=false;
    for(;captask.hasMoreElements();)   {
      Task task=(Task)captask.nextElement();
      PrepositionalPhrase pp=pp= task.getPrepositionalPhrase(MonitoringUtils.OtherPreposition) ;
      if(pp!=null)   {
	SendCapabilitiesObj capab=(SendCapabilitiesObj)pp.getIndirectObject();
	processCapabilities( capab);
      }
      
    }
  }
  
  /**
   * Called to update the local data structure for capabilites,consolidates
   * the capabilites of the manager and all its subordinates and register
   * the capabilites with the global yellow page Service .
   * 
   * @param capab  SendCapabilitesObj containing information about capabilities
   * @see  org.cougaar.core.security.oldmonitoring.Util.SendCapabilitiesObj
   */
  private void  processCapabilities(SendCapabilitiesObj capab)
  {
    if(MonitoringUtils.debug>0)
      System.out.println("process capabilities in manager"+capab.toString());
    Organization currentorg=capab.org;
    String name=currentorg.getUID().getOwner();
    boolean newservices=false;
    if(capab.Type.equalsIgnoreCase("Sensor"))  {
      for(int i=0;i<capab.Services.size();i++)  {
	String servicename= (String) capab.Services.elementAt(i);
	boolean contains= LocalYP_sensor.containsKey(servicename);
	if(contains)  {
	  Vector capableorg= (Vector) LocalYP_sensor.get( servicename);
	  if(!capableorg.contains( currentorg))  {
	    capableorg.add( currentorg);
	    LocalYP_sensor.put( servicename,capableorg);
	    newservices=true;
	    
	  }
	}
	else  {
	  Vector service=new Vector();
	  service.add(currentorg);
	  LocalYP_sensor.put( servicename,service);
	  newservices=true;
	}
      }
      
    }
    if(capab.Type.equalsIgnoreCase("Analyzer"))  {
      if(MonitoringUtils.debug>0)
	System.out.println("in managers  process capabilities for ana::::::::::");
      for(int i=0;i<capab.Services.size();i++) {
	String servicename= (String) capab.Services.elementAt(i);
	if(MonitoringUtils.debug>0)
	  System.out.println("In managers Plugin service name is :"+servicename);
	boolean contains= LocalYP_analyzer.containsKey(servicename);
	if(contains) {
	  Vector capableorg= (Vector) LocalYP_analyzer.get( servicename);
	  if(!capableorg.contains( currentorg))   {
	    capableorg.add( currentorg);
	    LocalYP_analyzer.put( servicename,capableorg);
	    newservices=true;
	  }
	}
	else  {
	  Vector service=new Vector();
	  service.add(currentorg);
	  LocalYP_analyzer.put( servicename,service);
	  newservices=true;
	}
      }
      
    }
    if(newservices)  {
      Vector sensors=new Vector();
      for(Enumeration e=LocalYP_sensor.keys();e.hasMoreElements();)   {
	String temp=(String)e.nextElement();
	sensors.add(temp);
      }
      Vector analyzers=new Vector();
      for(Enumeration e=LocalYP_analyzer.keys();e.hasMoreElements();)  {
	String temp=(String)e.nextElement();
	analyzers.add(temp);
      }
      SendManagerCapabilitiesObj managercapb=new SendManagerCapabilitiesObj(_self,sensors,analyzers);
      publishNewCapabilities(managercapb);
      
    }
  }
  
  
  /**
   * Finds the first sensor capable of providing the service specified in
   * the indirect object.Publishes task to the sensor to start
   * providing sensor data to Analyzer specified in the indirect object.
   * 
   * @param findinglist  Enumeration on Collection of newly added "Finding_Sensor" tasks
   * @see org.cougaar.core.security.oldmonitoring.Util.cmdObj
   * @see org.cougaar.core.security.oldmonitoring.Util.PublishCmdObj
   */
  private void process_findingsensor(Enumeration findinglist)
  {
    if(MonitoringUtils.debug>0)
      System.out.println("process_findingsensor in manager  ::::::::::::::::::::::::::");
    RootFactory theRF=getFactory();
    PublishCmdObj publishcmd;
    for(;findinglist.hasMoreElements();)  {
      Task tsk=(Task) findinglist.nextElement();
      if(MonitoringUtils.debug>0)
	System.out.println("In manager plugIn got find sensor task :"+tsk.toString());
      PrepositionalPhrase pp=tsk.getPrepositionalPhrase( MonitoringUtils.Reporting_Analyzer_Preposition);
          if(pp!=null) {
	    cmdObj cmd=(cmdObj) pp.getIndirectObject();
	    Vector sensor=(Vector)LocalYP_sensor.get(cmd.Type);
	    if(!sensor.isEmpty()) {
	      Organization sensororg=(Organization)sensor.elementAt(0);
	      publishcmd=new PublishCmdObj (cmd.Type,cmd.Analyzer_org);
	      Task  startpublishing=MonitoringUtils.createTask(theRF,publishcmd,MonitoringUtils.Start_publishing_Preposition,MonitoringUtils.Start_Publishing_Cmd);
	      doAllocation(sensororg,startpublishing);
	      Task  updaterouter=MonitoringUtils.createTask(theRF,publishcmd,MonitoringUtils.Start_publishing_Preposition,MonitoringUtils.Update_Router_cmd);
	      doAllocation(sensororg,updaterouter);
	    }
	    else  {
	      System.err.println("No sensor present to send publish cmd ");
	    }
	    
          }
          else  {
	    System.err.println("got wrong prep phrase  for start publish cmd");
          }
    }
  }
  
  /**
   * Creates  a "Query_Service " task with QueryTaskObj as indirect object
   * and publishes to the blackboard
   * 
   * @param queryobj QueryTaskObj
   * @see org.cougaar.core.security.oldmonitoring.Util.QueryTaskObj
   */
  private void publishQuerytask(QueryTaskObj queryobj)
  {
    if(_self!=null)  {
      queryobj.org= _self;
      Task task= MonitoringUtils.createTask(getFactory(),queryobj,MonitoringUtils.QueryPreposition,MonitoringUtils.Query_Services_Verb);
      publishAdd(task)  ;
    }
  }
  
  /**
   * Creates  a "UPDAT_Capabilities  " task with SendManagerCapabilitiesObj as indirect object
   * and publishes to the blackboard
   * 
   * @param queryobj QueryTaskObj
   * @see org.cougaar.core.security.oldmonitoring.Util.SendManagerCapabilitiesObj
   */
  private void publishNewCapabilities(SendManagerCapabilitiesObj managerobj)
  {
    if(_self!=null)  {
      managerobj.org=_self;
      Task task= MonitoringUtils.createTask(getFactory(),managerobj,MonitoringUtils.ManagerPreposition,MonitoringUtils.UPDATE_CAPABILITIES_Verb);
      publishAdd(task)  ;
    }
  }
  
  /**
   * Finds the self Organization from the list of Organization that satisfy the 
   * OrganizationPredicate.
   * 
   * @return  Organization that it part of.
   */
  
  protected Organization findself()
  {
    Organization org=null;;
    for (Iterator orgIter = allorganization.getCollection().iterator(); orgIter.hasNext();) {
      Organization currentorg = (Organization) orgIter.next();
      if(MonitoringUtils.debug>0)
	System.out.println("organization is :"+currentorg.toString());
      if (currentorg.isSelf())  {
	return currentorg;
      }
    }
    return org;
  }
  
  void dump (Vector vec)
  {
    for(int i=0;i<vec.size();i++) {
      Organization og=(Organization)vec.elementAt(i);
      System.out.println("In manager Plugin org found is :"+og.toString()+"at  ::"+i);
    }
  }
  
  /*
   protected boolean issubordinate(Organization  org)
   {
   //System.out.println("self is :::::::::::"+_self.toString());
   RelationshipSchedule schedule = _self.getRelationshipSchedule();
   
   Collection c= _self.getSubordinates(TimeSpan.MIN_VALUE,TimeSpan.MAX_VALUE);
   for(Iterator i=c.iterator();i.hasNext();)
   {
   Organization orgs=(Organization)schedule.getOther((Relationship)i.next());
   // System.out.println("org in sub is ::::::::::::::::"+orgs.toString());
           if(orgs.equals(org))
           {
	   return true;
	   
           }
	   }
	   return false;
	   
	   }
  */
  

  /**
   * "Start_Publishing_ui" Task received from the UIInterfacePlugin sends the request to
   *  Analyzer Manager provide analyzer capable of providing the service specified by indirect
   * object.If Analyzer manager referenced in indirect object is same as current manager then
   * it  creates a Reporting_Analyzer task with cmdObj as indirect object holding reference to
   * the Analyzer.
   * 
   * @param cmdtasklist
   *               Enumeration on Collection of newly added  "Start_Publishing_ui" Task
   * @see org.cougaar.core.security.oldmonitoring.util.cmdObj
   */
  
  protected void process_cmdTask(Enumeration cmdtasklist)
  {
    Task providing=null;
    RootFactory theRF=getFactory();
    for(;cmdtasklist.hasMoreElements();)  {
      Task tsk=(Task)cmdtasklist.nextElement();
      PrepositionalPhrase pp=tsk.getPrepositionalPhrase(MonitoringUtils.Cmd_Interface_Preposition);
      if(pp!=null)  {
	cmdObj cmd=(cmdObj)pp.getIndirectObject();
	if(cmd.Analyzer_org.getClusterIdentifier().getAddress().equalsIgnoreCase(_self.getClusterIdentifier().getAddress()))  {
	  if(MonitoringUtils.debug>0)
	    System.out.println("org is self and finding :::"+cmd.Type); 
	  Vector analyzer=(Vector)LocalYP_analyzer.get(cmd.Type);
	  if(!analyzer.isEmpty())  {
	    cmd.Analyzer_org=(Organization)analyzer.elementAt(0);
	    providing=MonitoringUtils.createTask(theRF,cmd,MonitoringUtils.Reporting_Analyzer_Preposition,MonitoringUtils.Reporting_Analyzer_Verb);
	    publishAdd(providing);
	    
	  }
	}
	else  {
	  if(MonitoringUtils.debug>0)
	    System.out.println("in manager doing allocation for finding analyzer::::::::::::"); 
	  doAllocation(cmd.Analyzer_org,tsk);
	}
      }
    }
  }
  
  /**
   * Allocation of task to organization specified in input parameter
   * 
   * @param org    Organization to which Task has to be allocated
   * @param task   Task which has to be allocated
   */
  protected void doAllocation(Organization org, Task task) 
  {
    if(MonitoringUtils.debug>0)
      System.out.println("In manager plugIn Doing allocation to org :"+org.toString()+"::::::::: For task ::::::"+task.toString());
    Predictor allocPred = org.getClusterPG().getPredictor();
    AllocationResult allocResult;
    if (allocPred != null)
      allocResult = allocPred.Predict(task, getDelegate());
    else
      allocResult = 
	PluginHelper.createEstimatedAllocationResult(
						     task, getFactory(), 0.0, true);
    Allocation myalloc = getFactory().createAllocation(
						       task.getPlan(), task, org, 
						       allocResult, Role.BOGUS);
    publishAdd(myalloc);
  }
  
}


