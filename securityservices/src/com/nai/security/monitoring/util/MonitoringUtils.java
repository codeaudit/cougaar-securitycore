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

import org.cougaar.domain.planning.ldm.asset.*;
import org.cougaar.domain.planning.ldm.plan.*;
import org.cougaar.domain.planning.ldm.RootFactory;
import java.util.Vector;
import java.util.Enumeration;


public class MonitoringUtils

{
    public static final String SEND_CAPABILITIES_Verb="Send_Capabilities";
    public static final String UPDATE_CAPABILITIES_Verb="UPDATE-YP-CAPABILITIES";
    public static final String Query_Services_Verb="QUERY_For_SERVICES";
    public static final String Query_PSP_Verb="QUERY_From_PSP";
    public static final String Response_Query_Verb="RESPONSE_For_QUERY";
    public static final String PROCESS_CAPABILITIES_Verb="Process_Capabilities";
    public static final String QueryPreposition="QueryFor";
    public static final String Query_PSP_Preposition="QueryFormPSP";
    public static final String ResponsePreposition="ResponseTo";
    public static final String ManagerPreposition="FromManager";
    public static final String OtherPreposition="FromOther";
    public static final String Cmd_Interface_Preposition="FromUIInterface";
    public static final String Cmd_Interface_Verb="Start_Publishing_ui";
    public static final String Reporting_Analyzer_Preposition="FromAnalyzer";
    public static final String Reporting_Analyzer_Verb="Reporting_Analyzer";
    public static final String Finding_Sensor_Verb="Finding_Sensor";
    public static final String Start_Publishing_Cmd="Start_Publishing";
    public static final String Start_publishing_Preposition="From_Manager_Publish_Cmd";
    public static final String Send_Sensor_Data="Send_Sensor_Data";
    public static final String Sensor_Data="Sensor_Data";
    public static final String Send_SensorData_Preposition="From_Sensor";
    public static final String Update_Router_cmd="Update_router";
    public static final String unavailable="Unknown PSP request!";

	public static int debug=0;
	static
	{
		String sdebug=System.getProperty("com.nai.security.monitoringdebug");
		if(sdebug.equalsIgnoreCase("true"))
		{
			debug=1;
		}
	}

    public static void setprep(NewTask ntask,Task original,RootFactory theRF)
    {
        Vector preps = new Vector();
        for(Enumeration e=original.getPrepositionalPhrases();e.hasMoreElements();)
        {
            PrepositionalPhrase pp=(PrepositionalPhrase)e.nextElement();
            NewPrepositionalPhrase npp = theRF.newPrepositionalPhrase();
            npp.setPreposition(pp.getPreposition());
            npp.setIndirectObject(pp.getIndirectObject());
            preps.add(npp);

        }
        ntask.setPrepositionalPhrases(preps.elements());
        
    }
	public static Task createTask(RootFactory theRF,Object indirectobject,String prepositionalPhrase,String verb)
	{
		NewTask new_task=theRF.newTask();
		new_task.setVerb(new Verb(verb));
		new_task.setDirectObject(null);
		// setting up Prepositional Phrase
		Vector preps=new Vector();
		NewPrepositionalPhrase new_pp=theRF.newPrepositionalPhrase();
		new_pp.setPreposition(prepositionalPhrase);
		new_pp.setIndirectObject(indirectobject);
		preps.add(new_pp);
		new_task.setPrepositionalPhrases(preps.elements());
		new_task.setPlan(theRF.getRealityPlan());
	if(debug>0)
	{
		System.out.println("Got indirect object to create new task *************:::"+indirectobject.toString());
		System.out.println("Got prep phrase for new task **********************::::"+prepositionalPhrase);
		System.out.println("Created new task "+new_task.toString());	
	}
	
		return new_task;
	} 
    public static  Vector parseString(String querystring,char delimiter)
    {
      
         Vector returnvec=new Vector();
         int startpt=0;
         int endpt=0;
         endpt=querystring.indexOf(delimiter) ;
         boolean inwhile=false;
         while(endpt>-1)
         {
             returnvec.add(querystring.substring(startpt,endpt));
             startpt=endpt+1;
             endpt=querystring.indexOf(delimiter,startpt);
             inwhile=true ;
          }
         //if(inwhile)
        // {
             // if(startpt>0)
            //  {
		if(debug>0)
                  System.out.println("in parsing of string :"+querystring.substring(startpt,querystring.length()));
                  returnvec.add(querystring.substring(startpt,querystring.length()));
             // }
        // }
        return returnvec;
     
    }
	public static String[] toStringArray(Vector vectordata)
	{
		if(vectordata.isEmpty())
		{
			return null;
		}
		String [] returndata=new String[ vectordata.size()];
		String tempdata=null;;
		for(int i=0;i<vectordata.size();i++)
		{
			tempdata=(String)vectordata.elementAt(i);
			returndata[i]=tempdata;
		}
		return returndata;
	}

  }

