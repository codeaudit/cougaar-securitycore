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
        


package com.nai.security.monitoring.util;


import org.cougaar.core.plugin.SimplePlugIn;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.cluster.IncrementalSubscription;

import org.cougaar.domain.planning.ldm.plan.HasRelationships;
import org.cougaar.domain.planning.ldm.plan.Relationship;
import org.cougaar.domain.planning.ldm.plan.RelationshipSchedule;
import org.cougaar.domain.planning.ldm.plan.Role;
import org.cougaar.domain.planning.ldm.plan.RoleSchedule;
import org.cougaar.domain.planning.ldm.plan.Schedule;
import org.cougaar.domain.planning.ldm.plan.ScheduleElement;
import org.cougaar.domain.planning.ldm.RootFactory;
import org.cougaar.core.plugin.util.PlugInHelper;

import org.cougaar.domain.planning.ldm.plan.*;
import org.cougaar.domain.planning.ldm.asset.*;
import org.cougaar.domain.glm.ldm.asset.*;

import org.cougaar.util.TimeSpan;

import org.cougaar.domain.glm.ldm.asset.Organization;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Collection;
import java.util.Collections;
import java.util.Vector;
import java.util.List;


/**
 *  OrgAllocation is responsible for allocation of task to capable agents
 */
public class OrgAllocatorPlugIn extends  SimplePlugIn
{
    
  private IncrementalSubscription allorganization,allSendTask,allupdatecapabilities,allQuerytask,allreportingtask,allupdaterouterTask,allRoutertable,allsensordata;
    
  /**
   * A predicate that matches all "Send_Capabilities" tasks
   */
  class SendTaskPredicate implements UnaryPredicate
  {
    /** 
     * @param o
     * @return true iff the object "passes" the predicate
     */
    public boolean execute(Object o) 
    {
      if(o instanceof Task)  {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.SEND_CAPABILITIES_Verb)) ;
      }
      return false;
    }
  }
  /**
   * A predicate that matches all "Send_Sensor_Data" tasks
   */
  class SensorDataTaskPredicate implements UnaryPredicate
  {
    /**
     * @param o
     * @return true iff the object "passes" the predicate
     */
    public boolean execute(Object o)
    {
      if(o instanceof Task)  {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.Send_Sensor_Data)) ;
      }
      return false;
    }
  }



  /**
   * 	A predicate that matches all "Update_Router_cmd" tasks
   */
  class UpdateRouterTaskPredicate implements UnaryPredicate
  {
    /**
     * @param o
     * @return true iff the object "passes" the predicate
     */
    public boolean execute(Object o)
    {
      if(o instanceof Task)  {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.Update_Router_cmd)) ;
      }
      return false;
    }
  }

  /**
   * A predicate that matches all "UPDATE_CAPABILITIES" tasks
   */
  class UpdateCapabilitiesPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      if(o instanceof Task)  {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.UPDATE_CAPABILITIES_Verb));
      }
      return false;
    }
  }
  /**
   * A predicate that matches all "RouterTask" tasks
   */
  class RouterTablePredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o)
    {
      return (o instanceof RouterTable);
    }
  }

  /**
   * A predicate that matches all "Query_Service" tasks
   */
  class QueryServicePredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      if(o instanceof Task)  {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.Query_Services_Verb));
      }
      return false;
    }
  }

  /**
   * A predicate that matches all "Reporting_Analyzer" tasks
   */
  class ReportingTaskPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      if(o instanceof Task)  {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.Reporting_Analyzer_Verb));
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
  /** Called during initialization to set up subscriptions.
   * More precisely, called in the plugin's Thread of execution
   * inside of a transaction before execute will ever be called.
   **/
  protected void setupSubscriptions() 
  {
    allorganization=(IncrementalSubscription)subscribe(new OrganizationPredicate());
    allSendTask=(IncrementalSubscription)subscribe(new SendTaskPredicate());
    allupdatecapabilities=(IncrementalSubscription)subscribe(new UpdateCapabilitiesPredicate());
    allQuerytask=(IncrementalSubscription)subscribe(new QueryServicePredicate());
    allreportingtask= (IncrementalSubscription)subscribe(new ReportingTaskPredicate());
    allupdaterouterTask= (IncrementalSubscription)subscribe(new UpdateRouterTaskPredicate());
    allRoutertable= (IncrementalSubscription)subscribe(new RouterTablePredicate());
    allsensordata= (IncrementalSubscription)subscribe(new SensorDataTaskPredicate());
    publishAdd(new RouterTable());

  }

  /**
   * Called inside of an open transaction whenever the plugin was
   * explicitly told to run or when there are changes to any of
   * our subscriptions.
   **/
  protected void execute() 
  {
    if(MonitoringUtils.debug>0)  {    
      System.out.println("In allocators execute");
	//dump(  allorganization.getCollection(),"from execute of allocator");
    }
    Collection c=null;
    c=allSendTask.getCollection();
    if(!c.isEmpty())  {
      if(MonitoringUtils.debug>0)
	System.out.println("all send task is not empty in OrgAllocator ");
      process_SendTask(allSendTask.getCollection().iterator());
    }
    c=allupdatecapabilities.getAddedCollection();
    if(!c.isEmpty())  {
      if(MonitoringUtils.debug>0)
	System.out.println("all update capabilities is not empty in OrgAllocator");
      process_UpdateYp(Collections.enumeration(c));
    }
    c=allQuerytask.getAddedCollection();
    if(!c.isEmpty())  {
      if(MonitoringUtils.debug>0)
	System.out.println("all query task is not empty in OrgAllocator");
      process_QueryTask(Collections.enumeration(c));
    }
    c=allreportingtask.getAddedCollection();
    if(!c.isEmpty())  {
      if(MonitoringUtils.debug>0)
	System.out.println("all reporting task is not empty");
      process_ReportingTask(Collections.enumeration(c));
    }
    c=allupdaterouterTask.getAddedCollection();
    if(!c.isEmpty())  {
      if(MonitoringUtils.debug>0)
	System.out.println("all update router task is not empty in allocator ");
      process_UpdateRouterTask(Collections.enumeration(c));
    }
    c=allsensordata.getAddedCollection();
    if(!c.isEmpty())  {
      if(MonitoringUtils.debug>0)
	System.out.println("all sensor data is not empty");
      process_SensorData(Collections.enumeration(c));
    }

  }
  protected void process_UpdateRouterTask(Enumeration updateRouterlist)
  {
    RouterTable rtable=null;
    Collection routertablecollection=allRoutertable.getCollection();
    if(routertablecollection.size()>1)  {
      System.err.println("More than one routertable found::::");
    }
    for(Iterator i=routertablecollection.iterator();i.hasNext();)  {
      rtable=(RouterTable)i.next();
    }
    if(MonitoringUtils.debug>0)  {
      Enumeration keys=rtable.routertable.keys();
      if(keys!=null)  {
	for(;keys.hasMoreElements();)  {
	  String key=(String)keys.nextElement();
	  if(MonitoringUtils.debug>0)
	    System.out.println("*******************  Keys in UpdateRouterTask in orgAllocator :::::::"+key);
	  Vector orgs=(Vector)rtable.routertable.get(key);	
	  for(int i=0;i<orgs.size();i++)  {
	    Organization oo=(Organization)orgs.elementAt(i);
	    if (MonitoringUtils.debug>0)
	      System.out.println("org is :"+oo.toString());
	  }
	}
      }
      else  {
	System.out.println("router table is empty******");
      }
    }

    for(;updateRouterlist.hasMoreElements();)   {
      Task tsk=(Task)updateRouterlist.nextElement();
      PrepositionalPhrase pp=tsk.getPrepositionalPhrase(MonitoringUtils.Start_publishing_Preposition);
      if(pp!=null)  {
	PublishCmdObj publishcmdobj=(PublishCmdObj)pp.getIndirectObject();
	if(rtable.routertable.containsKey(publishcmdobj.Type))  {
	  Vector org=(Vector)rtable.routertable.get(publishcmdobj.Type);
	  if(!org.contains(publishcmdobj.Analyzer_org))   {
	    org.add(publishcmdobj.Analyzer_org);
	    rtable.routertable.put(publishcmdobj.Type,org);
	  }
	}
	else  {
	  Vector org=new Vector();
	  org.add(publishcmdobj.Analyzer_org);
	  rtable.routertable.put(publishcmdobj.Type,org);
	  if(MonitoringUtils.debug>0)  {
	    System.out.println("Adding org to router table ::::"+org.toString()+"type is ::::::::"+publishcmdobj.Type);
	    Enumeration keys=rtable.routertable.keys();	
	    for(;keys.hasMoreElements();)  {
	      String gotkey=(String)keys.nextElement();
	      System.out.println("key after adding in ORG Allocator is :"+gotkey);
	    }
	  }
	}
      }
      else  {
	System.err.println("got wrong prep Phrase for updateRouter cmd");
      }	
    }
    publishChange(rtable);	
  }
  
  
  protected void process_SensorData(Enumeration sensordatalist)
  {
    
    RouterTable rtable=null;
    Task tsk=null;
    RootFactory theRF=getFactory();
    Collection routertablecollection=allRoutertable.getCollection();
    if(routertablecollection.size()>1)  {
      System.err.println("More than one routertable found in process_SensorData in ORG Allocator  ::::");
    }
    for(Iterator i=routertablecollection.iterator();i.hasNext();)  {
      rtable=(RouterTable)i.next();
    }
    if(MonitoringUtils.debug>0)  {
      Enumeration keys=rtable.routertable.keys();
      if(keys!=null)  {
	for(;keys.hasMoreElements();)   {
	  String key=(String)keys.nextElement();
	  System.out.println("*******************  Keys in ORG allocator process_SensorData:::::::"+key);
	  Vector orgs=(Vector)rtable.routertable.get(key);	
	  for(int i=0;i<orgs.size();i++) {
	    Organization oo=(Organization)orgs.elementAt(i);
	    System.out.println("org is :"+oo.toString());
	  }
	}
      }
      else
	System.out.println("got keys as empty in send sensor data in allloc");
    }
    String source=null;
    SensorDataObj sensordata=null;
    Organization destorg=null;
    for(;sensordatalist.hasMoreElements();)  {
      tsk=(Task)sensordatalist.nextElement();
      if(MonitoringUtils.debug>0)   {
	System.out.println("inside for for sending data in allocator:::"+tsk.toString());
      }
      source=tsk.getSource().getAddress();
      PrepositionalPhrase pp=tsk.getPrepositionalPhrase(MonitoringUtils.Send_SensorData_Preposition);
      if(pp!=null)   {
	sensordata=(SensorDataObj)pp.getIndirectObject();
	if(MonitoringUtils.debug>0)
	  System.out.println("type in sensor is :::"+sensordata.type);
	if(rtable.routertable.containsKey(sensordata.type)) {
	  Vector orgcontainer=(Vector)rtable.routertable.get(sensordata.type);
	  NewTask ntask=theRF.newTask();
	  ntask.setVerb(new Verb(MonitoringUtils.Sensor_Data));
	  MonitoringUtils.setprep(ntask,tsk,theRF);
	  for(int i=0;i<orgcontainer.size();i++)   {
	    destorg=(Organization)orgcontainer.elementAt(i);
	    if(!destorg.getClusterIdentifier().getAddress().equals(source))  {
	      if(MonitoringUtils.debug>0)
		System.out.println("Going to do allocation for sensor data to org in ORG allocator ::::::::::::::"+destorg.toString());
	      doAllocation(destorg,ntask);
	    }
	    else {
	      System.out.println(" in same agent :::");
	      publishAdd(ntask);
	    }
	  }
	}
	else  {
	  System.err.println("No information available in router table");
	}		
      }
      else  {
	System.err.println("Got wrong prep phrase for sensordata task::");	
      }
    }
    
  }

  /**
   * Processes the "SEND_CAPABILITIES_Verb" task.It gets the list of task
   * that satisfy SendTaskPredicate published by either a sensor/analyzer
   * changes the  verb of the task to PROCESS_CAPABILITIES_Verb keeping all
   * PrepositionPhrases and indirect object same as the original task .Find's
   * superior and allocates the newly created task to superior . Task's that 
   * has been processes are removed .
   * 
   * @param sendtask Iterator on Collection of "SEND_CAPABILITIES_TASK"
   */
  private void  process_SendTask(Iterator sendtask)
  {
    
    for(Iterator e=sendtask;e.hasNext();)  {
      Task task=(Task)e.next();
	if(MonitoringUtils.debug>0)
	  System.out.println("Got task in allocatorfor capabilities and going to call fine superior "+ task.toString());
	Organization org=findSuperior();
             
	if(org!=null)  {
	  if(MonitoringUtils.debug>0)
	    System.out.println("Got superior in ORG Allocator :"+org.toString());
	  NewTask ntask=getFactory().newTask();
	  ntask.setVerb(new Verb(MonitoringUtils.PROCESS_CAPABILITIES_Verb));
	  MonitoringUtils.setprep(ntask,task,getFactory());
	  doAllocation(org,ntask);
	  sendtask.remove();
	}
	else   {
	  if(MonitoringUtils.debug>0)
	    System.out.println("Could not find superior for task ::::::::"+task.toString());
	}
    }
  }

  /**
   * Processes all received task of type "Query_Service" . This task is received
   * from the Monitoring Manager and it is allocated to the Organization that is capable
   * of providing the "yellow page service"
   * 
   * @param query
   */
  private void process_QueryTask(Enumeration query)
  {
    for(Enumeration e=query;e.hasMoreElements();)  {
      Task task=(Task)e.nextElement();
      if(MonitoringUtils.debug>0)
	System.out.println("Got task in ORG allocator for Query :::::: "+ task.toString());
      Organization org=findCapableOrg("YellowPageService");
      if(org!=null)  {
	if(MonitoringUtils.debug>0)
	  System.out.println("Got capable org in process_QueryTask for YellowPageService :"+org.toString());
	    /*    Was doing an over head of creating new task
                    
		  NewTask ntask=getFactory().newTask();
		  ntask.setVerb(new Verb(MonitoringUtils.Query_Services_Verb));
		  MonitoringUtils.setprep(ntask,task,getFactory());
	    */
	doAllocation(org,task);
      }
      else   {
	System.out.println("Could not find capable org  for task ::::::::"+task.toString());
      }
    }

  }

  /**
   * Processes all newly added "UPDATE_CAPABILITIES" tasks.Find the Organization
   * that is capable of providing "Yellow Page Service" and allocating the task
   * to that organization.
   * 
   * @param capabilities
   *               Enumeration on Collection of "UPDATE_CAPABILITIES" tasks.
   */
  /*
    Note - If it is not able to find organization capable of providing "yellow page Service 
    then it just prints out to console and continues with the next task in the list.Also note 
    that allocation result is monitered to check whether the allocation has been successful 
    or no. 
  */
  private void process_UpdateYp(Enumeration capabilities)
  {
    if(MonitoringUtils.debug>0)
      System.out.println("in process updateYp in ORG Allocator  :::::::::::::");
    Organization org=findCapableOrg("YellowPageService");
    for(Enumeration e=capabilities;e.hasMoreElements();)   {
      Task task=(Task)e.nextElement();
      if(MonitoringUtils.debug>0)
	System.out.println("Got task in ORG  allocator for  process_UpdateYp"+ task.toString());
      if(org!=null)  {	
	if(MonitoringUtils.debug>0)
	  System.out.println("Got capable org  in ORG  allocator for capabilities YellowPageService:"+org.toString());
	/*   Was doing an over head of creating new task 
                    
	     NewTask ntask=getFactory().newTask();
	     ntask.setVerb(new Verb(MonitoringUtils.UPDATE_CAPABILITIES_Verb));
	     MonitoringUtils.setprep(ntask,task,getFactory());
	*/
	doAllocation(org,task);
      }
      else  {
	System.out.println("Could not find capable org for capabilities YellowPageService  in process_UpdateYp of ORG Allocator. Task is  :::::::::"+task.toString());
      }
    }
    
  }

  /**
   * Processes all "Reporting_Analyzer" tasks.This task is received from the
   * analyzer that is reporting for service for the sensor that has requested
   * for service of the analyzer. "Reporting_Analyzer" Task is taken and it verb is
   * changed to "Finding_Sensor" with all the PrepositionalPhrases and indirect object
   * of the original task are kept intact. Newly created task is allocated to Sensor
   * Organization specified in the indirect object of the PrepositionalPhrase
   * "Reporting_Analyzer_Preposition".Sensor Organization in the indirect object is
   * Superior Organization of the Sensor .i.e  Manager
   * 
   * @param reportingtasklist
   *               Enumeration on Collection of "Reporting_Analyzer" task
   */
  private void process_ReportingTask(Enumeration reportingtasklist)
  {
    for(;reportingtasklist.hasMoreElements();)   {
      Task tsk=(Task) reportingtasklist.nextElement();
      PrepositionalPhrase pp= tsk.getPrepositionalPhrase(MonitoringUtils.Reporting_Analyzer_Preposition);
      if(pp!=null)  {
	cmdObj cmd=(cmdObj)pp.getIndirectObject();
	NewTask ntask=getFactory().newTask();
	ntask.setVerb(new Verb(MonitoringUtils.Finding_Sensor_Verb));
	MonitoringUtils.setprep(ntask,tsk,getFactory());
	doAllocation(cmd.Sensor_org,ntask);
	
      }
      else   {
	System.out.println("Got wrong pp in ORG  allocator's process_ReportingTask  form analyzers manager");
      }
    }
  }
    
   
  /**
   * Find the superior of the current Organization. Iterates through Collection of organization that satisfy
   * the OrganizationPredicate .
   * 
   * @return  First organization that satify the superior Relationship. If there are none that match the 
   *         superior relationship then it returns null.
   */
  protected Organization findSuperior()
  {
    Organization org=null;
    if(MonitoringUtils.debug>0)  {
      dump(allorganization.getCollection(),"From find superior in Org allocator ::::::::::");
      System.out.println("Finding Superior:");
    }
    for (Iterator orgIter = allorganization.getCollection().iterator(); orgIter.hasNext();)   {
      Organization currentorg = (Organization) orgIter.next();
      if(MonitoringUtils.debug>0)  {
	System.out.println("Finding Superior in ORG Allocator :");
	System.out.println("Current organization is :"+currentorg.toString());
      }
      if (currentorg.isSelf())   {
	RelationshipSchedule schedule = currentorg.getRelationshipSchedule();
	Collection superior=currentorg.getSuperiors(TimeSpan.MIN_VALUE,TimeSpan.MAX_VALUE);
	if(MonitoringUtils.debug>0)  {
	  System.out.println("Check for superior collection is empty in ORG Allocator :"+ superior.isEmpty());
	  dump(superior,"From inside of iterator loop in ORG Allocatoes find superior");
	}
	for (Iterator iter = superior.iterator(); iter.hasNext();)   {
	  HasRelationships other = schedule.getOther( (Relationship)iter.next());
	  if (other instanceof Organization)  {                               
	    org=(Organization)other     ;
	    if(MonitoringUtils.debug>0)
	      System.out.println("IN ORG Allocators find Superior is  "+org.toString());
	    return org;
	  }
	  else  {
	    System.out.println("could not find org");
	  }
	}
      }
    }
    return org;
  }

  /**
   * Find the Organization that is capable of providing  role specified as
   * input parameter to the function.If there are multiple Organization that
   * satisfy the role the the first Organization is returned.If no Organization satisfy
   * the given role, then null is returned.
   * 
   * @param role   Name of the Role
   * @return First Organization that satisfy the role . Null is returned in case when 
   *         none of the Organization satisfy the role.
   */
  private Organization findCapableOrg(String role)
  {

    if(MonitoringUtils.debug>0)
      System.out.println ("OrgAllocatorPlugIn: find Capable Organization");
    Vector capaborg=new Vector();
    boolean first=true;
    // find ourself first
    for (Iterator orgIter = allorganization.getCollection().iterator(); orgIter.hasNext();)   {
      Organization org = (Organization) orgIter.next();
      if(MonitoringUtils.debug>0)
	System.out.println("organization is :"+org.toString());
      if (org.isSelf())   {
	RelationshipSchedule schedule = org.getRelationshipSchedule();
	Role roleobj = Role.getRole(role);		
	if(MonitoringUtils.debug>0)    {
	  System.out.println("Created role for search in ORG Allocators findCapableOrg ::::::::::::"+roleobj.getName());
	  System.out.println ("searching for role: " + role );
	}
	Collection orgCollection = schedule.getMatchingRelationships(roleobj);
	if(orgCollection.isEmpty())  {
		System.out.println("Got capable org as empty in ORG Allocators findCapableOrg:::::::::::::::for role ::::::::::::::"+role);
	}
	for (Iterator iter = orgCollection.iterator(); iter.hasNext();)   {
	  HasRelationships other = schedule.getOther((Relationship)iter.next());
	  if(MonitoringUtils.debug>0)
	    System.out.println("other is ::::::::::::::::"+other.toString());
	  if (other instanceof Organization)  {
	    if (first)  {
	      capaborg.add(other);
	    }
	    else  {
	      if (!capaborg.contains(other))  {
		iter.remove();
	      }
	    }
	  }
	}
	first = false;
      }
      
      // If we found more that one match the we just return the first one 
    }
    if (capaborg.size() > 0)  {
      Organization selectedOrganization = (Organization)capaborg.elementAt(0);
      return(selectedOrganization);
    }
    else  {
      System.out.println("found no org capable of role  in ORG Allocators findCapableOrg ::"+role);
    }
    return(null);
  }
  /**
   * Allocation of task to organization specified in input parameter
   * 
   * @param org    Organization to which Task has to be allocated
   * @param task   Task which has to be allocated
   */
  protected  void doAllocation(Organization org, Task task) 
  {
    if(MonitoringUtils.debug>0)
      System.out.println("Doing allocation to org  in ORG Allocators doAllocation :"+org.toString()+"::::::::: For task ::::::"+task.toString());
    Predictor allocPred = org.getClusterPG().getPredictor();
    AllocationResult allocResult;
    if (allocPred != null)
      allocResult = allocPred.Predict(task, getDelegate());
    else
      allocResult = 
	PlugInHelper.createEstimatedAllocationResult(
						     task, getFactory(), 0.0, true);
    Allocation myalloc = getFactory().createAllocation(
						       task.getPlan(), task, org, 
						       allocResult, Role.BOGUS);
    publishAdd(myalloc);
  }

  void dump(Collection c ,String from)
  {
    if(c!=null)   {
      System.out.println("Going to dump superior" +from);
      for(Iterator i=c.iterator();i.hasNext();) {
	System.out.println("Found $$$$$:"+i.next().toString());
      }
    }
  }
  
}
