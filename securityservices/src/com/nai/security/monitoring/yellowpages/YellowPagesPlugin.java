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



package com.nai.security.monitoring.yellowpages;

import java.util.Vector;
import java.util.Iterator;
import java.util.Enumeration;
import java.util.Hashtable;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.SimplePlugin;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.core.domain.RootFactory;
import org.cougaar.glm.ldm.asset.Organization;

import org.cougaar.util.UnaryPredicate;



import com.nai.security.monitoring.util.*;

/**
*
*/

public class YellowPagesPlugin extends SimplePlugin
{
    private Hashtable Sensors_yp;
    private Hashtable Analyzers_yp;

    private IncrementalSubscription allCapabilitiesTask,allQueryTask;

    class CapabilitiesTaskPredicate implements UnaryPredicate
    {
        /** @return true iff the object "passes" the predicate */
        public boolean execute(Object o) 
        {
          if(o instanceof Task)
          {
              Task task=(Task)o;
             return  task.getVerb().equals(MonitoringUtils.UPDATE_CAPABILITIES_Verb);
          }
          return false;
            
        }
    }
    class QueryTaskPredicate implements UnaryPredicate
    {
        /** @return true iff the object "passes" the predicate */
        public boolean execute(Object o) 
        {
          if(o instanceof Task)
          {
              Task task=(Task)o;
             return  task.getVerb().equals(MonitoringUtils.Query_Services_Verb);
          }
          return false;
            
        }
    }
      /**
     * Called inside of an open transaction whenever the plugin was
     * explicitly told to run or when there are changes to any of
     * our subscriptions.
     **/
    protected void execute() 
    {
        if(MonitoringUtils.debug>0)
		System.out.println("In exec of YP:::::::::::");
        Enumeration captasks= allCapabilitiesTask.getAddedList();
        processcapabilitiestask(captasks) ;
        Enumeration querytask=  allQueryTask.getAddedList();
        process_Querytask(querytask);
        
        
    }
    /** Called during initialization to set up subscriptions.
     * More precisely, called in the plugin's Thread of execution
     * inside of a transaction before execute will ever be called.
     **/
    protected void setupSubscriptions() 
    {
        Sensors_yp=new Hashtable();
        Analyzers_yp=new Hashtable();
        allCapabilitiesTask=(IncrementalSubscription)subscribe(new CapabilitiesTaskPredicate());
        allQueryTask=(IncrementalSubscription)subscribe(new QueryTaskPredicate());
    }
    private void   process_Querytask( Enumeration e)
    {
        if(MonitoringUtils.debug>0)
        	System.out.println("GOT task for query ");
        for(;e.hasMoreElements();)
        {
            Task task=(Task)e.nextElement();
	    if(MonitoringUtils.debug>0)
            	System.out.println("GOT task for query ::::::::::::"+task.toString());
            PrepositionalPhrase pp=task.getPrepositionalPhrase(MonitoringUtils.QueryPreposition);
            if(pp!=null)
            {
               QueryTaskObj query=(QueryTaskObj) pp.getIndirectObject();
               processQueryObject(query);

            }
            else
            {
                System.out.println("got a wrong task in yp service in process query ::::::");
            }
        }


    }
    private void  processcapabilitiestask(Enumeration e)
    { 
        if(MonitoringUtils.debug>0)
        	System.out.println("GOT task for update ");
        for(;e.hasMoreElements();)
        {
            Task task=(Task)e.nextElement();
        	if(MonitoringUtils.debug>0)
            		System.out.println("got task for update of capab :"+task.toString());
            PrepositionalPhrase pp=task.getPrepositionalPhrase(MonitoringUtils.ManagerPreposition);
            if(pp!=null)
            {
               SendManagerCapabilitiesObj manager=(SendManagerCapabilitiesObj) pp.getIndirectObject();
               processcapabilitiesObject(manager);

            }
            else
            {
                System.out.println("got a wrong task in yp service ::::::");
            }
        }
    }
     private void  processQueryObject (QueryTaskObj query)
     {
         Vector Sensororg;
         Vector Analyzerorg;
         if(  Sensors_yp.containsKey(query.Type))
         {
             Sensororg=(Vector)Sensors_yp.get(query.Type);

         }
         else
         {
              Sensororg=new Vector()  ;
         }
        if(MonitoringUtils.debug>0)
        	 dumpvector(Sensororg);
         if(Analyzers_yp.containsKey(query.Type))
         {
             Analyzerorg=(Vector)Analyzers_yp.get( query.Type)  ;
         }
         else
         {
           Analyzerorg=new Vector();
         }
        if(MonitoringUtils.debug>0)
        	 dumpvector( Analyzerorg);
         ResponseObj robj= new ResponseObj(query.org,Sensororg,Analyzerorg,query.Type,query.unique_id);
         Task task=MonitoringUtils.createTask(getFactory(),robj,MonitoringUtils.ResponsePreposition,MonitoringUtils.Response_Query_Verb);
         publishAdd(task);


     }
    private void  processcapabilitiesObject (SendManagerCapabilitiesObj manager)
    {
       for(int i=0;i<manager.Sensors.size();i++)
       {
           String service=(String) manager.Sensors.elementAt(i);
           if(  Sensors_yp.containsKey(service))
           {
               Vector sensor=(Vector)Sensors_yp.get(service);
               if(!sensor.contains(manager.org))
               {
                   sensor.add(manager.org);
                   Sensors_yp.put( service,sensor);
               }
           }
           else
           {
               Vector sensor=new Vector();
               sensor.add(manager.org);
                Sensors_yp.put( service,sensor);

           }
       }
        if(MonitoringUtils.debug>0)
	{
       		System.out.println("Sensors in yp::::");
       		dumphashtable(Sensors_yp);
	}
       for(int i=0;i<manager.Analyzers.size();i++)
       {
           String service=(String) manager.Analyzers.elementAt(i);
           if(  Analyzers_yp.containsKey(service))
           {
               Vector analyzer=(Vector)Analyzers_yp.get(service);
               if(!analyzer.contains(manager.org))
               {
                   analyzer.add(manager.org);
                   Analyzers_yp.put( service,analyzer);
               }
           }
           else
           {
               Vector analyzer=new Vector();
               analyzer.add(manager.org);
               Analyzers_yp.put( service,analyzer);

           }
       }
        if(MonitoringUtils.debug>0)
	{
       		System.out.println("Analyzers in yp::::");
       		dumphashtable(Analyzers_yp);
	}
    }
    void dumpvector(Vector v)
    {
        for(int i=0;i<v.size();i++)
        {
            Organization org=(Organization)v.elementAt(i);
            System.out.println("element at "+ i+"  :"+org.getUID().getOwner());
        }
    }
    void dumphashtable(Hashtable h)
    {
        Enumeration keys=h.keys();
        for(;keys.hasMoreElements();)
        {
            String Key=(String )keys.nextElement();
            Vector vec=(Vector) h.get(Key);
            dumpvector(vec);
        }
    }


}
