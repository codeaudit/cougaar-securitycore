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
import java.net.*;
import java.util.*;
import com.nai.security.monitoring.util.*;
import org.cougaar.domain.glm.ldm.asset.Organization;


public class PSP_AnalyzerList extends PSP_BaseAdapter implements PlanServiceProvider, UISubscriber
{
    
    
   /** Creates new PSP_Search */
    public PSP_AnalyzerList()
    {
       super(); 
    }
    
    public PSP_AnalyzerList( String pkg, String id ) throws RuntimePSPException
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
		Vector allnames=new Vector();
                Vector alllinks=new Vector();
                psc.getAllURLsAndNames(alllinks,allnames);
		String surl;
		StringBuffer sburl;
		Vector analyzerlink=new Vector();
		Vector analyzername=new Vector();
		for(int i=0;i<alllinks.size();i++)
		{
			
			surl=(String)alllinks.elementAt(i);
			sburl=new StringBuffer(surl);
			sburl.append("Threats.PSP");
			//System.out.println("URL is :"+sburl.toString());
			try
			{
				URL isanalyzerurl=new URL(sburl.toString());
				URLConnection urlcon=isanalyzerurl.openConnection();
				urlcon.setDoInput(true);
				InputStream is=urlcon.getInputStream();
				StringBuffer bdata=new StringBuffer();
				int data=0;
		        	while ((data=is.read())!=-1)
				{
					bdata.append((char)data);
				}
				//System.out.println("data received is :"+bdata.toString());
				if(bdata.toString().indexOf(MonitoringUtils.unavailable)==-1)
				{
					analyzerlink.add(surl);
					analyzername.add((String)allnames.elementAt(i));
					if(MonitoringUtils.debug>0)
						System.out.println("analyzer is at :"+surl);
				}
				is.close();
				is=null;	
				//urlcon.close();
				
			}
			catch (Exception excp)
			{
				System.err.println("Got URL EXception");
				excp.printStackTrace();
			}
			
		}
			printLinksToAnalyzer(out,analyzerlink,analyzername);
                out.println("<p><p><p>");
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

			out.flush();
			out.close();

    }
	public void printLinksToAnalyzer(PrintStream out,Vector links,Vector Names)
	{
		out.println("<HTML>\n");
		out.print("<body>\n");
		out.print("<h2> List of Analyzers present in system </h2>\n");
		out.print("<p>\n");
		System.out.println("size of links are ::"+links.size()+"size of name are "+Names.size());
		int length=links.size();
		for(int i=0;i<length;i++)
		{
			out.print("<p>\n");
			out.print("<a href=\""+(String)links.elementAt(i)+"Threats.PSP\">");
			out.print((String)Names.elementAt(i)+"</a>\n");
		}

		out.print("</body>\n");
		out.print("</HTML>\n");
		//out.flush();
		//out.close();
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
    
}

