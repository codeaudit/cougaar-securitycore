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



package com.nai.security.monitoring.sensors;

import java.util.Vector;
import java.util.Iterator;
import java.util.Enumeration;
import java.util.Date;
import java.util.Hashtable;
import java.io.*;

import org.apache.xerces.parsers.DOMParser;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.EntityResolver;
import org.w3c.dom.Document;

import org.cougaar.glm.ldm.asset.Organization;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.mlm.plugin.ldm.LDMEssentialPlugin ;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.core.domain.RootFactory;
import org.cougaar.util.UnaryPredicate;

import com.nai.security.monitoring.util.*;
import com.nai.security.util.SecurityPropertiesService;
import org.cougaar.core.security.crypto.CryptoServiceProvider;


/**
 * SensorPlugin is a Sensor that publishes it capabilities to it superior,
 * publishes sensor data for analyzers. SensorPlugin sleeps for 1 minute and 
 * publishes sensor data.Only publishes sensor data requested by user .
 */

public class SensorPlugin extends LDMEssentialPlugin
{
  private SecurityPropertiesService secprop = null;

  Vector Services ;
  Vector currentlypublishing;
  Organization self;
  final String Type="Sensor";
  FileInputStream [] fi=null;
  String [] nodename=null;
  long sleeptime=1000l;
  boolean publishedcapabilities=false;
  private IncrementalSubscription allorganization,allcmd;

    
  public SensorPlugin() {
    // TODO. Modify following line to use service broker instead
    secprop = CryptoServiceProvider.getSecurityProperties();
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
   * A predicate that matches all "Start_Publishing_Cmd" tasks
   */
  class PublishCmdPredicate implements UnaryPredicate
  {
    /** @return true iff the object "passes" the predicate */
    public boolean execute(Object o) 
    {
      if( o instanceof Task)  {
	Task task=(Task)o;
	return (task.getVerb().equals(MonitoringUtils.Start_Publishing_Cmd));
      }
      return false;
    }
  }
  
  /**
   * Called inside of an open transaction whenever the plugin was
   * explicitly told to run or when there are changes to any of
   * our subscriptions.
   * 
   **/
  public void execute() 
  {
    if(MonitoringUtils.debug>0)  {
      System.out.println("In exec of Sensor");
    }
    if(!publishedcapabilities)  {
      if(MonitoringUtils.debug>0)
	System.out.println("In Sensor Plugin publishing capabilities");
      publishedcapabilities=publishcapabilities();
      File filelist=null;
      if(Services.contains("SecurityException") )   {
	String filename=secprop.getProperty(secprop.BOOTSTRAP_LOGFILE);
	if(filename!=null)  {
	  int lastindex=filename.lastIndexOf(File.separator);
	  filename=filename.substring(0,lastindex);
	  filelist=new File(filename);
	}
	else  {
	  if(MonitoringUtils.debug>0)
	    System.out.println("Could not get the log file name for security exception through java property .Probably org.cougaar.core.security.bootstrap.SecurityManagerLogFile is not set ---- using default values");
	  String cougaarpath=secprop.getProperty(secprop.COUGAAR_INSTALL_PATH);
	  StringBuffer logfilepath=new StringBuffer();
	  logfilepath.append(cougaarpath);
	  if(MonitoringUtils.debug>0)
	    System.out.println("got cougaar install path"
			       +logfilepath.toString());
	  logfilepath.append(File.separatorChar);
	  logfilepath.append("log"+File.separatorChar+"bootstrap"
			     +File.separator);
	  if(MonitoringUtils.debug>0)
	    System.out.println("IN Sensor Plugin got log  path"
			       +logfilepath.toString());
	  filelist=new File(logfilepath.toString());
	}
	String [] filenames=null;
	if(filelist!=null)  {
	  filenames=filelist.list();
	  if((filenames!=null)&&(filenames.length>0))   {
	    if(MonitoringUtils.debug>0)   {	
	      for(int i=0;i<filenames.length;i++) {
		System.out.println("file name at : "+ i+"  :: "+filenames[i]);
	      }
	    }
	    String [] uniquelog=findUniquePerNode(filenames,filelist,"SecurityManager");
	    if(MonitoringUtils.debug>0)  {	
	      for(int i=0;i<uniquelog.length;i++)  {
		System.out.println("file name unique at : "+ i+"  :: "+uniquelog[i]);
	      }
	    }
	    fi = new FileInputStream[uniquelog.length];
	    File tempfile=null;
	    for(int i=0;i<uniquelog.length;i++)  {
	      tempfile=new File(filelist,uniquelog[i]);
	      try  {
		fi[i]=new FileInputStream(tempfile);
	      }
	      catch(IOException ioexp)  {
		System.err.println("Error while opening file stream for file :::  "+tempfile.toString());
		ioexp.printStackTrace();
	      }
	    }
	    nodename=findNodeName(fi);
	    for(int i=0;i<uniquelog.length;i++)   {
	      tempfile=new File(filelist,uniquelog[i]);
	      try  {
		fi[i]=new FileInputStream(tempfile);
	      }
	      catch(IOException ioexp)   {
		System.err.println("Error while opening file stream for file :::  "+tempfile.toString());
		ioexp.printStackTrace();
	      }
	    }
	  }
	}
      }
    }
    
    process_publishCmd(allcmd.getAddedList());
    double slp=Math.random();
    double crit=Math.random();
    while((crit*10)>4||((crit*10)==0))  {
      crit=Math.random();
      // System.out.println("crit while gen is :"+crit*10);
    }
    slp*=10*0.6;
    sleeptime=((int)slp)*100000l;
    if(sleeptime==0)   {
      sleeptime=1000000l;
    }
    publishdata();
    wakeAfter(sleeptime);
    
  }
  
  private String[] findUniquePerNode(String[] filenames,File dir,String typeexcep)
  {
    String [] onlysecuritymanager=findfiles(typeexcep,filenames);
    String [] findUniquelog=findlatest(onlysecuritymanager,dir);
    return findUniquelog;
  }
  private String[] findlatest(String[] onlysecuritym,File dir)
  {
    Hashtable list=new Hashtable();
    String filename;
    Vector parsed;
    Vector similarlist;
    String Key;
    if(onlysecuritym!=null)  {
      for(int i=0;i<onlysecuritym.length;i++)   {
	filename=onlysecuritym[i];
	parsed=MonitoringUtils.parseString(filename,'_');
	if(MonitoringUtils.debug>0)  {
	  for(int z=0;z<parsed.size();z++)  {
	    System.out.println("parsed data is : "+z+"  ::  "+(String)parsed.elementAt(z));
	  }
	}
	if(parsed.size()>2)  {
	  Key=(String)parsed.elementAt(1);
	  if(list.containsKey(Key))   {
	    similarlist=(Vector)list.get(Key);
	    similarlist.add(filename);
	    list.put(Key,similarlist);
	  }
	  else   {
	    similarlist=new Vector();
	    similarlist.add(filename);
	    list.put(Key,similarlist);
	  }
	}
	else  {
	  System.err.println("Error in parsing the log file name::"+filename);
	}
      }
    }
    Enumeration keylist=list.keys();
    String nodename;
    String latestfile=null;
    Date latestdate=null;
    Date tempdate;	
    File completepath;
    parsed=new Vector();
    long ldate;
    for(;keylist.hasMoreElements();)   {
      nodename=(String)keylist.nextElement();
      similarlist=(Vector)list.get(nodename);
      
      for(int i=0;i<similarlist.size();i++) {
	filename=(String)similarlist.elementAt(i);
	if(latestdate==null)   {
	  completepath=new File(dir,filename);
	  ldate=completepath.lastModified();
	  latestdate=new Date(ldate);
	  latestfile=filename;	
	}
	else  {
	  completepath=new File(dir,filename);
	  ldate=completepath.lastModified();
	  tempdate=new Date(ldate);
	  if(tempdate.after(latestdate))   {
	    latestdate=tempdate;
	    latestfile=filename;
	  }
	  latestfile=filename;	
	  
	}
      }
      if(latestfile!=null)
	parsed.add(latestfile);
      else
	System.err.println("Could not get latest file for ::"+nodename);
      latestdate=null;
      latestfile=null;
    }
    return MonitoringUtils.toStringArray(parsed);
    
  }
  
  private String[] findfiles(String startswith,String[] filelist)
  {
    Vector foundfiles=new Vector();
    String temp;
    if(filelist==null)   {
      return MonitoringUtils.toStringArray(foundfiles);
    }
    if(filelist.length>0)  {
      for( int i=0;i<filelist.length;i++) {
	temp=filelist[i];
	if(temp.startsWith(startswith))   {
	  foundfiles.add(new String(temp));
	}
      }
    }
    return MonitoringUtils.toStringArray(foundfiles);
  }
  
  private String[] findNodeName(FileInputStream [] fileis)
  {
    String[] NodeName=new String[fileis.length];
    for(int i=0;i<fileis.length;i++)  {
      int length=0; 
      byte [] by=new byte[0];
	try  {
	  if(fileis[i]!=null)  {
	    length =fileis[i].available();
	    by=new byte[length];
	    fileis[i].read(by);
	    //fileis[i].reset();
	  }
	}
	catch(IOException ioexp)   {
	  ioexp.printStackTrace();
	}
	
	String newdata=new String(by);
	String delimiterstart=new String("<nodeName>");
	String delimiterend=new String ("</nodeName>");
	int startindex=newdata.indexOf(delimiterstart);
	int endindex=newdata.indexOf(delimiterend);
	String nodename=null;
	if((startindex>-1)&&(endindex>-1))   {
	  nodename=newdata.substring(startindex,endindex);
	  NodeName[i]=nodename;
	  
	}
	
    }
    return NodeName;
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

  public boolean publishcapabilities()
  {
    boolean published=false;
    if(self==null)  {
      if(MonitoringUtils.debug>0)
	System.out.println("Self was null in Sensor Plugin ");
	self=findself();
	if(self!=null)  {
	  if(  Services.isEmpty())  {
	    for(Iterator e=self.getOrganizationPG().getRoles().iterator();e.hasNext();)  {
	      String role=(( Role)e.next()).getName();
	      if(MonitoringUtils.debug>0)
		System.out.println("In Sensor Plugin publishcapabilities Role :"+role);
	      if(role.startsWith(Type,0))  {
		int index=role.indexOf('-');
		if(index==-1)  {
		  System.out.println("Got a wrong format from ini file");
		}
		else  {
		  Services= MonitoringUtils.parseString(role.substring(index+1),':');
		}
	      }
	      
	    }
	    if(MonitoringUtils.debug>0)  {
	      // System.out.println("Got roles first time is:::::::::::::::::: :"+Services.toString());
	      DumpVector(Services);
	    }
	  }
	}
	
    }
    if(self!=null)   {
      if(MonitoringUtils.debug>0) {
	System.out.println("In sensor Plugin Creating send cap obj:%%%%%%%%%%%%%%%%%%%%%%%%%"+publishedcapabilities);
	DumpVector(   Services);
	System.out.println("first time going to publish capabilities::::::::");
      }
      SendCapabilitiesObj obj=new SendCapabilitiesObj(self,Type,Services);
      if(MonitoringUtils.debug>0)
	System.out.println("In Sensor Plugin services to be send ="+obj.toString());
      Task task= MonitoringUtils.createTask(getFactory(),obj,MonitoringUtils.OtherPreposition,MonitoringUtils.SEND_CAPABILITIES_Verb);
      publishAdd(task)  ;
      published=true;
                    
    }
    return published;
  }

  /** publishes only requested sensor data
   *
   */
  public void  publishdata()
  {
    RootFactory theRF=getFactory();
    if(! currentlypublishing.isEmpty())  {
      Task sensortask=null;
      SensorDataObj sensordata=null;
      for(int i=0;i<currentlypublishing.size();i++)  {
	String type=(String) currentlypublishing.elementAt(i);
	System.out.println("In Sensor Plugin publishdata Type is :::::::::::::"+type);
	if(type.equalsIgnoreCase("SecurityException") )  {
	  if(fi.length>0)  {
	    for(int z=0;z<fi.length;z++)  {
	      Vector data=getsecurityevent(fi[z]);
	      if(!data.isEmpty())  {
		for(int j=0;j<data.size();j++)  {
		  sensordata= new SensorDataObj((String)currentlypublishing.elementAt(i),new Date(System.currentTimeMillis()),(String)data.elementAt(j),nodename[z]);
		  sensortask=MonitoringUtils.createTask(theRF,sensordata,MonitoringUtils.Send_SensorData_Preposition,MonitoringUtils.Send_Sensor_Data);
		  publishAdd(sensortask);
		  if(MonitoringUtils.debug>0)
		    System.out.println("*****In sensor Plugin  publishing security excep::****************************");
		}
	      }
	      else  {
		if(MonitoringUtils.debug>0)
		  System.out.println("In Sensor Plugin  got data vector for publishing security empty ********************************");
	      }
	    }
	  }
	}
	else   {
	  if(MonitoringUtils.debug>0)
	    System.out.println("Currently publishing::::"+(String)currentlypublishing.elementAt(i));
	  sensordata=new SensorDataObj((String)currentlypublishing.elementAt(i),new Date(System.currentTimeMillis()),(String)currentlypublishing.elementAt(i));
	  sensortask=MonitoringUtils.createTask(theRF,sensordata,MonitoringUtils.Send_SensorData_Preposition,MonitoringUtils.Send_Sensor_Data);
	  publishAdd(sensortask);
	}
      }
    }
  }

  /** Called during initialization to set up subscriptions.
   * More precisely, called in the plugin's Thread of execution
   * inside of a transaction before execute will ever be called.
   **/
  protected void setupSubscriptions() 
  {
    Services = new Vector();
    currentlypublishing=new Vector();
    //DumpVector(Services);
    allorganization=(IncrementalSubscription)subscribe(new OrganizationPredicate());
    allcmd =(IncrementalSubscription)subscribe(new PublishCmdPredicate());
  }
  
  private void  DumpVector(Vector ser)
  {
    System.out.println("In Sensor Plugin Services got through ini.dat is :");
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
    for (Iterator orgIter = allorganization.getCollection().iterator(); orgIter.hasNext();)
      {
	Organization currentorg = (Organization) orgIter.next();
	if(MonitoringUtils.debug>0)	
	  System.out.println("IN Sensor PlugIN findself organization is :"+currentorg.toString());
	if (currentorg.isSelf())  {
	  return currentorg;
	}
      }
    return org;
  }
  
  /**
   * Process "Start_publishing_Cmd" task .It update internal data structure for
   * kind of sensor data user has requested for.
   * 
   * @param publichcmdlist
   *               Enumeration on Collection of newly Start_publishing_Cmd
   * @see com.nai.security.monitoring.util.PublishCmdObj
   */
  protected void process_publishCmd(Enumeration publichcmdlist)
  {
    PublishCmdObj pcmd;
    for(; publichcmdlist.hasMoreElements();)  {
      Task tsk=(Task) publichcmdlist.nextElement();
      PrepositionalPhrase pp=tsk.getPrepositionalPhrase(MonitoringUtils.Start_publishing_Preposition);
      if(pp!=null)  {
	pcmd=(PublishCmdObj) pp.getIndirectObject();
	if( !currentlypublishing.contains(pcmd.Type))  {
	  currentlypublishing.add(pcmd.Type);
	  if(MonitoringUtils.debug>0)	
	    System.out.println("In sensor Plugin  process_publishCmd Add ::::::::"+pcmd.Type+" to current publishing list");
	}
	
      }
    }
  }


  protected Vector getsecurityevent(FileInputStream fileis) 
  {
    int length=0; 
    byte [] by=new byte[0];
    //DOMParser parser=null;
    //InputSource isource=null;
    try  {
      if(fileis!=null)  {
	length =fileis.available();
	by=new byte[length];
	fileis.read(by);
      }
      /* was trying to run xml parser. Having problems will look into it later
	 if(fi!=null)
	 {
	 parser=new DOMParser();
	 // parser.setEntityResolver(new ConfigResolver());
	 isource=new InputSource(fi);
	 parser.parse(isource);
	 }
      */
    }
    /*
      catch(SAXException saxexp)
      {
      saxexp.printStackTrace();
      }*/
    catch(IOException ioexp)  {
      ioexp.printStackTrace();
    }
    String newdata=new String(by);
    String delimiterstart=new String("<securityEvent>");
    String delimiterend=new String ("</securityEvent>");
    int startindex=0;
    int endindex=0;
    int lastpt=0;
    Vector data=new Vector();
    startindex=newdata.indexOf(delimiterstart);
    endindex=newdata.indexOf(delimiterend);
    while((startindex>-1)&&(endindex>-1))  {
      data.add(newdata.substring(startindex,endindex));
      lastpt=startindex;
      startindex=newdata.indexOf(delimiterstart,endindex);
      endindex=newdata.indexOf(delimiterend,startindex);
      
    }
    //data.add(newdata.substring(lastpt,newdata.length()));
    return data;
                  
  }
  
  public Asset getPrototype(java.lang.String aTypeName,java.lang.Class anAssetClassHint)
  {
    return null;
  }
  public void fillProperties(Asset asset)
  {
  }

    
}

