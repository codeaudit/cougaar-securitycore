
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


import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.cluster.*;
import org.cougaar.domain.planning.ldm.plan.*;
import org.cougaar.lib.planserver.*;
import org.cougaar.domain.planning.ldm.RootFactory;

import java.io.*;
import java.net.URLEncoder;
import java.util.*;
import com.nai.security.monitoring.util.*;
import org.cougaar.domain.glm.ldm.asset.Organization;




public class PSP_Assign extends PSP_BaseAdapter implements PlanServiceProvider, UISubscriber
{
    
    
   /** Creates new PSP_Search */
    class responsePredicate implements UnaryPredicate
    {
        /** @return true iff the object "passes" the predicate */
        public boolean execute(Object o) 
        {
            return (o instanceof ResponseObj);
        }
    }
    public PSP_Assign()
    {
       super(); 
    }
    
    public PSP_Assign( String pkg, String id ) throws RuntimePSPException
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
	if(MonitoringUtils.debug>0)
        	System.out.println("assign psp got called $$$$$$$$$$$$$$$$$$$$$$$");
        if(query_parameters.isPostRequest())
        {
		if(MonitoringUtils.debug>0)
            	System.out.println("is post");
            //Vector v=query_parameters.getBodyAsString();
            //for(int i=0;i<v.size();i++)
            //{ 
                String x= query_parameters.getBodyAsString();
		if(MonitoringUtils.debug>0)
                	System.out.println("got resp element"+x);
                Vector vec=MonitoringUtils.parseString(x,'&');
            //}  
                String type=null;
                String Sensor=null;
                String id=null;
                long unique_id=0;
                String Analyzer=null;
                if(!vec.isEmpty())
                {
                    if(vec.size()>3)
                    {
                        type=(MonitoringUtils.parseString(vec.elementAt(0).toString(),'=')).elementAt(1).toString();
			if(MonitoringUtils.debug>0)
                        	System.out.println("type is :"+type);
                         id=(MonitoringUtils.parseString(vec.elementAt(1).toString(),'=')).elementAt(1).toString();
			if(MonitoringUtils.debug>0)
                        	 System.out.println("id  in string is  :"+id);
                         try
                         {
                            Long lg=new Long (id.trim());
                           unique_id=lg.longValue();
                            System.out.println("id  in long  is  :"+unique_id);

                         }
                         catch(Exception exp)
                         {
                             exp.printStackTrace();
                         }

                        Sensor=(MonitoringUtils.parseString(vec.elementAt(2).toString(),'=')).elementAt(1).toString();
			if(MonitoringUtils.debug>0)
                        	System.out.println("Sensor is :"+Sensor);
                        Analyzer=(MonitoringUtils.parseString(vec.elementAt(3).toString(),'=')).elementAt(1).toString();
			if(MonitoringUtils.debug>0)
                        	System.out.println("analyzer is :"+Analyzer);
                    }
                    else
                    {
                        System.out.println("Error in url parameter");
                    }
                }
               Collection response=psc.getServerPlugInSupport().queryForSubscriber(new responsePredicate());
               Vector responsetasks= getResponseObj(response,unique_id);
               if(responsetasks.size()> 1)
               {
                   System.out.println("too many response::::::::::");
               }
               ResponseObj  robj=(ResponseObj)responsetasks.elementAt(0);
               Organization sensororg= findOrg(robj,Sensor,"sensor");
               Organization analyzerorg=findOrg(robj,Analyzer,"Analyzer");
               cmdObj cmd= new cmdObj(type,sensororg, analyzerorg);
               psc.getServerPlugInSupport().publishAddForSubscriber(cmd);
               out.println("<html>");
		out.println( "<body>");
		out.print("<h2> Started providing sensor data for event" +type+"</h2>");
		out.println("Details" );
		out.println("<ul>");
		out.println("<li> Sensor from manager agent:"+sensororg.getClusterPG().getClusterIdentifier().getAddress()+"</li>");

		out.println("<li> analyzer from manager agent:"+analyzerorg.getClusterPG().getClusterIdentifier().getAddress()+"</li>");
		out.println("</ul>");
		out.println("<p>");
		ServerPlugInSupport sps;

  		// url and cluster info
 		String clusterID;
 		String encodedClusterID;
  		String base_url;
  		String cluster_url;
  		String cluster_psp_url;
 		String psp_path;

		 sps = psc.getServerPlugInSupport();
    		// url and cluster info
    		clusterID = sps.getClusterIDAsString();
    		encodedClusterID = URLEncoder.encode(clusterID);
    		int port = psc.getLocalPort();
    		String loc;
    		try {
      			loc = psc.getLocalAddress().getLocalHost().getHostAddress();
    			} catch (Exception e) {
     			 System.err.println("UNABLE TO FIND HOST!");
      			loc = "UNKNOWN";
    		}
    		base_url = "http://"+loc+":"+port+"/";
    		cluster_url = base_url+"$"+encodedClusterID;
		if (clusterID != null) {
      		out.print("<a href=\""+cluster_url+"/Search.PSP\">");
      		// link to cluster
      		out.print("Search </a> ");
    		} 
		else 
		{
      			out.print("<font color=red>Unknown cluster</font>");
    		}


                for(int i=0;i<responsetasks.size();i++)
                {
			if(MonitoringUtils.debug>0)
                    		System.out.println("vec element at ::"+i+responsetasks.elementAt(i).toString());
                }
              
        }
        else
        {
             System.out.println("not a post response");

        }
	out.flush();
	out.close();
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

    public Organization findOrg(ResponseObj obj,String Name,String service)
    {
        Organization org =null;
        if(service.equalsIgnoreCase("sensor"))
        {
            for(int i=0;i<obj.Sensors.size();i++)
            {
                 Organization orgn=(Organization)obj.Sensors.elementAt(i);
                if(orgn.getClusterIdentifier().getAddress().equalsIgnoreCase(Name))
                {
                    org=orgn;
                    return org ;
                }
            }
     

        }
        if(service.equalsIgnoreCase("analyzer") )
        {
            for(int i=0;i<obj.Analyzers.size();i++)
            {
                 Organization orgn=(Organization)obj.Analyzers.elementAt(i);
                if(orgn.getClusterIdentifier().getAddress().equalsIgnoreCase(Name))
                {
                 org=orgn;
                 return org;
                }
            }

        }
        return org;
    }

     
     /*
     boolean contains(Vector org, String Name)
     {
         boolean contain=false;
         for(int i=0;i<org.size();i++)
         {
             Organization orgn=(Organization)org.elementAt(i);
             if(orgn.getClusterIdentifier().getAddress().equalsIgnoreCase(Name))
             {
                 contain=true;
             }
         }
         return contain;
     }
     */
     Vector getResponseObj(Collection response,long id)
     {
         Vector  responsevector=new Vector();
         for(Iterator i=response.iterator();i.hasNext();)
         {
             ResponseObj resobj=(ResponseObj)i.next();
             if(resobj.unique_id==id)
             {
                responsevector.add( resobj);
             }
         }
         return  responsevector;

     }
     
}

