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



package org.cougaar.core.security.oldmonitoring.util;


import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.domain.RootFactory;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.glm.ldm.asset.*;
import org.cougaar.core.plugin.SimplePlugin;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.TimeSpan;
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.Vector;
import java.util.Iterator;
import java.util.Collection;
import java.util.HashSet;
import org.cougaar.core.security.oldmonitoring.util.*;


/** 
*    
*   This class is the interface between the PSP_Search and the agent.It creates a
*   query task on behalf of the PSP and returns the response of the search to the 
*   PSP.
*    
**/


public class UIInterfacePlugin extends org.cougaar.core.plugin.SimplePlugin
{
    
  private IncrementalSubscription allorganization,
    allquerypsptask,
    allresponseTask,
    allcmd;
  private Organization _self;
  
  class OrganizationPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      return( o instanceof Organization) ;
    }
  }

  class SearchPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      return o instanceof Query;
    }
  }
  
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

  class AssignPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      return (o instanceof cmdObj);
    }
  }

    
  /**
   * Called inside of an open transaction whenever the plugin was
   * explicitly told to run or when there are changes to any of
   * our subscriptions.
   **/
  protected void execute() 
  {
    Enumeration Query =allquerypsptask.getAddedList();
    if(_self!=null)   {
      processquery(Query);
    }
    else   {
      _self=findself();
      if(_self!=null)  {
	processquery(Query);
      }
    }
    Enumeration eresponsetask=allresponseTask.getAddedList();
    processResponse(eresponsetask);
    Enumeration cmdlist= allcmd.getAddedList();
    process_cmd(cmdlist);
    
  }
  protected void setupSubscriptions() 
  {
    allorganization=(IncrementalSubscription)subscribe(new OrganizationPredicate());
    allquerypsptask=(IncrementalSubscription)subscribe(new SearchPredicate());
    allresponseTask=(IncrementalSubscription)subscribe(new ResponseTaskPredicate());
    allcmd=(IncrementalSubscription)subscribe(new AssignPredicate());
    
  }

  /**
     Finds self organization from the list of organization known to the agent
          
  **/
  protected Organization findself()
  {
    Organization org=null;;
    for (Iterator orgIter = allorganization.getCollection().iterator(); orgIter.hasNext();)  {
      Organization currentorg = (Organization) orgIter.next();
      if(MonitoringUtils.debug>0)
	System.out.println("IN UIinterfaces findself organization is :"+currentorg.toString());
      if (currentorg.isSelf())   {
	return currentorg;
      }
    }
    return org;
  }
  
  /**
     Creates a Query task with indirect object set as Instance of QueryTaskObj
  **/
  
  protected Task createQueryTask( RootFactory theRF, QueryTaskObj  obj, String verb)
  {
    NewTask new_task = theRF.newTask();
    new_task.setVerb(new Verb(verb));
    new_task.setDirectObject(null);
    setPrepPhrasesQuery (new_task, obj, theRF );
    new_task.setPlan(theRF.getRealityPlan());
    return(new_task);
    
  }

  /**
     sets the PrepositionalPhrase & indirect object  for the new task created in 
     createQueryTask.PrepositionalPhrase is set to "QueryFor".
  **/
  protected void  setPrepPhrasesQuery(NewTask task, QueryTaskObj  obj  ,RootFactory theRF)
  {
    Vector preps = new Vector(0);
    NewPrepositionalPhrase npp = theRF.newPrepositionalPhrase();
    npp.setPreposition(MonitoringUtils.QueryPreposition);
    npp.setIndirectObject(obj);
    preps.add(npp);
    task.setPrepositionalPhrases(preps.elements());
    
  }
  
  private void publishQuerytask(QueryTaskObj queryobj)
  {
    if(_self!=null)   {
      queryobj.org= _self;
      Task task= createQueryTask(getFactory(),queryobj,MonitoringUtils.Query_Services_Verb);
      publishAdd(task)  ;
    }
  }
  
  /**
     processes list of query received from PSP_Search in form of a Query Object.
     Processing include's creating of New Query Task and publishing.
     
  **/
  
  protected void processquery(Enumeration e)
  {
    for(;e.hasMoreElements();)   {
      Query  qtsk=(Query)e.nextElement();
      QueryTaskObj qu=new QueryTaskObj(_self,qtsk.Type,qtsk.unique_id);
      if(MonitoringUtils.debug>0)
	System.out.println("Going to publish query in UIInterfaces processquery :"+qtsk.Type);
      publishQuerytask(qu);
      
    }
  }
  
  /**
     processes list of query received from PSP_Search in form of a Query Object.
     Processing include's creating of New Query Task and publishing.
     
  **/
  private void  processResponse(Enumeration restask)
  {
    if(MonitoringUtils.debug>0)
      System.out.println("got response task in UIInterfaces processResponse ::::::::::::");
    for(;restask.hasMoreElements();)   {
      Task task=(Task)restask.nextElement();		
      if(MonitoringUtils.debug>0)
	System.out.println("In UIInterfaces processResponse .Response task is  :"+task.toString()); 
      PrepositionalPhrase pp=task.getPrepositionalPhrase(MonitoringUtils.ResponsePreposition);
      if(pp!=null)   {
	ResponseObj obj=(ResponseObj)pp.getIndirectObject();
	if(MonitoringUtils.debug>0)
	  System.out.println("published response obj in UIInterfaces processResponse");
	publishAdd(obj);
      }
      else   {
	System.out.println("got response task without prep in UIInterfaces processResponse:"+task.toString());
      }
    }
  }
   
  private void process_cmd(Enumeration cmdlist)
  {
    if(MonitoringUtils.debug>0)
      System.out.println("in cmd processing in UiInterface :::::::::::::::::");
    cmdObj cmd=null;
    RootFactory theRF=getFactory();
    for(;cmdlist.hasMoreElements();)   {
      cmd=(cmdObj)cmdlist.nextElement();
      Task cmdtask=createCmdTask(theRF,cmd,MonitoringUtils.Cmd_Interface_Verb);
      publishAdd(cmdtask);
    }
  }

  protected Task createCmdTask( RootFactory theRF, cmdObj  obj, String verb)
  {
    NewTask new_task = theRF.newTask();
    new_task.setVerb(new Verb(verb));
    new_task.setDirectObject(null);
    setPrepPhrasesCmd (new_task, obj, theRF );
    new_task.setPlan(theRF.getRealityPlan());
    return(new_task);
    
  }

  /**
     sets the PrepositionalPhrase & indirect object  for the new task created in 
     createQueryTask.PrepositionalPhrase is set to "QueryFor".
  **/
  protected void  setPrepPhrasesCmd(NewTask task, cmdObj  obj  ,RootFactory theRF)
  {
    Vector preps = new Vector(0);
    NewPrepositionalPhrase npp = theRF.newPrepositionalPhrase();
    npp.setPreposition(MonitoringUtils.Cmd_Interface_Preposition);
    npp.setIndirectObject(obj);
    preps.add(npp);
    task.setPrepositionalPhrases(preps.elements());
    
  }
    
}
