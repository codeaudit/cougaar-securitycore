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


import org.cougaar.core.plugin.SimplePlugin;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.planning.ldm.plan.HasRelationships;
import org.cougaar.planning.ldm.plan.Relationship;
import org.cougaar.planning.ldm.plan.RelationshipSchedule;
import org.cougaar.planning.ldm.plan.Role;
import org.cougaar.planning.ldm.plan.RoleSchedule;
import org.cougaar.planning.ldm.plan.Schedule;
import org.cougaar.planning.ldm.plan.ScheduleElement;
import org.cougaar.core.domain.RootFactory;
import org.cougaar.core.plugin.util.PluginHelper;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.glm.ldm.asset.*;
import org.cougaar.util.TimeSpan;
import org.cougaar.glm.ldm.asset.Organization;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Collection;
import java.util.Vector;
import java.util.List;
import java.util.Date;


/**
 * YPAllocatorPlugin allocates the search result in form of a Task  back to the 
 * organization  that requested to it.It is plugin which is part of the cluster that has
 * Yellow Page Service plugin
 */
public class YPAllocatorPlugin extends  SimplePlugin
{
  
  private IncrementalSubscription allResponsetask;
    
  /**
   * A predicate that matches all "Response_For_Query" tasks
   */
  class ResponseTaskPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      if(o instanceof Task)  {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.Response_Query_Verb)) ;
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
    allResponsetask=(IncrementalSubscription)subscribe(new ResponseTaskPredicate());
    
  }
  
  /**
   * Called inside of an open transaction whenever the plugin was
   * explicitly told to run or when there are changes to any of
   * our subscriptions.
   **/
  protected void execute() 
  {
    System.out.println("In YP allocators execute");
    process_Responsetask(allResponsetask.getAddedList());
    
  }

  /**
   * Processes all newly added "Response_For_Query" tasks.Takes the ResponseObj which is
   * stored as indirect object in PrepositionalPhrase "ResponseTo" and allocates the
   * task to organization specified in the ResponseObj.
   * 
   * @param responsetask
   *               Enumeration on Collection of "Response_For_Query" tasks
   * @see com.nai.security.util.ResponseObj
   */
  private void  process_Responsetask(Enumeration responsetask)
  {
    
    for(Enumeration e=responsetask;e.hasMoreElements();)  {
      Task task=(Task)e.nextElement();
      // System.out.println("Got task in yp allocator "+ task.toString());
      PrepositionalPhrase pp= task.getPrepositionalPhrase(MonitoringUtils.ResponsePreposition);      
      if(pp!=null)  {
	// System.out.println("Got pp in yp allocator  :"+pp.toString());
	ResponseObj robj=(ResponseObj)pp.getIndirectObject();
	if(MonitoringUtils.debug>0)
	  System.out.println("IN YPAllocators process_Responsetask Going to do allocation to  ::" + robj.org.toString());
	doAllocation(robj.org,task);
      }
      else {
	System.out.println("IN YPAllocators process_Responsetask could not find appropriate prep for response task ::::::"+task.toString());
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
      System.out.println("Doing allocation IN YPAllocators doAllocation  to org :"+org.toString()+"::::::::: For task ::::::"+task.toString());
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

  /**
   * Prints the Response_for_Query collection on to console. For debug purpose only
   * 
   * @param c
   * @param from
   */
  void dump(Collection c ,String from)
  {
    if(c!=null)  {
	System.out.println("Going to dump Related ORG  in YPAllocator " +from);
	for(Iterator i=c.iterator();i.hasNext();)   {
	  System.out.println("Found $$$$$:"+i.next().toString());
	}
    }
  }
  
}
