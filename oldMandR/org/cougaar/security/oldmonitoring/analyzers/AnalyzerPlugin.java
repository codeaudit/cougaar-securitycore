
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




package org.cougaar.core.security.oldmonitoring.analyzers;

import java.util.Vector;
import java.util.Iterator;
import java.util.Enumeration;

import org.cougaar.glm.ldm.asset.Organization;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.SimplePlugin;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.core.domain.RootFactory;
import org.cougaar.util.UnaryPredicate;

import org.cougaar.core.security.oldmonitoring.util.*;

/**
 * AnalyzerPlugin is a Analyzer that publishes it capabilities to it superior,
 * provide data to analyzers to analyze.
 */
public class AnalyzerPlugin extends SimplePlugin
{
  Vector Services ;
  Organization self;
  final String Type="Analyzer";
  boolean publishedcapabilities=false;
  private IncrementalSubscription allorganization,alldata;
  
  class OrganizationPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      return( o instanceof Organization) ;
      
    }
  }
  class DataPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      if( o instanceof Task)   {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.Sensor_Data));
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
      System.out.println("In exec of Analyzer");
    if(!publishedcapabilities)  {
      if(MonitoringUtils.debug>0)
	System.out.println("in publishing capabilities in analyzer ");
      publishedcapabilities=publishcapabilities();
    }
    process_data(alldata.getAddedList());
    
  }
  
  /** Called during initialization to set up subscriptions.
   * More precisely, called in the plugin's Thread of execution
   * inside of a transaction before execute will ever be called.
   **/
  protected void setupSubscriptions() 
  {
    Services = new Vector();
    //DumpVector(Services);
    allorganization=(IncrementalSubscription)subscribe(new OrganizationPredicate());
    alldata= (IncrementalSubscription)subscribe(new DataPredicate());
    
  }

  /**
   * Publishes capabilities to it superior in form of a Task with verb<b> SEND_CAPABILITIES_Verb</B>.
   * It first find the Organization it is associated with and then reads capabilities from roles
   * specified in clustername-prototype-ini.dat.
   * <P>
   * <B>Note Roles are specified for sensor/analyzer plugins in different format
   * compared to roles specified in Ultra*Log cluster.</B>
   * </P>
   * <BR>
   * for e.g
   * <BR>
   * Roles specified in a typical prototype-ini.dat is<BR>
   * [OrganizationPG] <BR>
   * Roles                Collection<Role>   "StrategicTransportationProvider,TransportationProvider"<BR>
   * <BR>
   * Roles specified for sensor/analyzer prototype-ini.dat is <BR>
   * 
   * [OrganizationPG] <BR>
   * Roles                Collection<Role>   "Sensor-POD:TCPSCAN,Analyzer-TCPSCAN"<BR>
   */
  private boolean  publishcapabilities()
  {
    boolean published=false;
    if(self==null)  {
      if(MonitoringUtils.debug>0)
	System.out.println("Self was null in analyzer PlugIN  ");
      self=findself();
      if( (Services.isEmpty())&&(self!=null))  {
	for(Iterator e=self.getOrganizationPG().getRoles().iterator();e.hasNext();)  {
	  String role=(( Role)e.next()).getName();
	  if(MonitoringUtils.debug>0)
	    System.out.println("Role in analyzer  :"+role);
	  if(role.startsWith(Type,0))  {
	    int index=role.indexOf('-');
	    if(index==-1)  {
	      System.err.println("Got a wrong format from ini file");
	    }
	    else  {
	      if(MonitoringUtils.debug>0)
		System.out.println("role after substring in analyzer is :"+ role.substring(index+1));
	      Services= MonitoringUtils.parseString(role.substring(index+1),':');
	    }
	  }
	}
	if(MonitoringUtils.debug>0)  {
	  System.out.println("In Analyzer PlugIN Got roles first time is:::::::::::::::::: :"+Services.toString());
	  DumpVector(Services);
	}
      }
      
    }
    if(self!=null)  {	
      if(MonitoringUtils.debug>0) {
	System.out.println("IN ANALYZER PLUGIN Creating send cap obj:");
	DumpVector(Services);
      }
      SendCapabilitiesObj obj=new SendCapabilitiesObj(self,Type,Services);
      if(MonitoringUtils.debug>0)
	System.out.println("services to be send ="+obj.toString());
      Task task= MonitoringUtils.createTask(getFactory(),obj,MonitoringUtils.OtherPreposition,MonitoringUtils.SEND_CAPABILITIES_Verb);
      publishAdd(task)  ;
      published=true;
    }
    return published;
  }
  
  /**
   *  Processes the task with verb Send_Sensor_data.
   * 
   * @param enumdata Enumeration of Task's with verb  Send_Sensor_Data
   */
  private void process_data(Enumeration enumdata)
  {
    if(MonitoringUtils.debug>0)
      System.out.println("got data to analyze");
    for(; enumdata.hasMoreElements();)  {
      Task tsk=(Task)enumdata.nextElement();
      if(MonitoringUtils.debug>0)
	System.out.println("Got task to analyze"+tsk.toString());
    }
  }
  
  /**
   *  Prints Roles vector to console.For debug purpose only.
   * 
   * @param ser
   */
  private void  DumpVector(Vector ser)
  {
    System.out.println("In analyzer Plugin Services got through param is :");
    for(int i=0;i<ser.size();i++)  {
      System.out.println((String)ser.elementAt(i));
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
    for (Iterator orgIter = allorganization.getCollection().iterator(); orgIter.hasNext();)  {
      Organization currentorg = (Organization) orgIter.next();
      // System.out.println("organization is :"+currentorg.toString());
      if (currentorg.isSelf())  {
	return currentorg;
      }
    }
    return org;
  }
  
}

