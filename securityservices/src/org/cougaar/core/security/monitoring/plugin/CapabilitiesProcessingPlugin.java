/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */


package org.cougaar.core.security.monitoring.plugin;

import java.util.Enumeration;
import java.util.Collection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Vector;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.service.*;
import org.cougaar.core.security.monitoring.idmef.*;

import org.cougaar.core.security.monitoring.blackboard.*;
import edu.jhuapl.idmef.*;



/**
 * A predicate that matches all "Event object with registration "
 */
class CapabilitiesPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof Event ) {
      Event e=(Event)o;
      IDMEF_Message msg=e.getEvent();
      if(msg instanceof Registration){
	return true;
      }
    }
    return ret;
  }
}


/**
 * A predicate that matches all CapabilitiesObject
 */
class CompleteCapabilitiesPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CapabilitiesObject ) {
      return true;
    }
    return ret;
  }
}

/**
 * Predicate that matches all ConsolidateCapabilities
 *
 */
class ConsolidatedCapabilitiesPredicate implements UnaryPredicate{
 public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof Event ) {
      Event e=(Event)o;
      IDMEF_Message msg=e.getEvent();
      if(msg instanceof AgentRegistration){
	return true;
      }
    }
    return ret;
  }
}

/**
 *
 **/

public class CapabilitiesProcessingPlugin
  extends ComponentPlugin
{

  // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;

  private IncrementalSubscription capabilities;
    
  private IncrementalSubscription completecapabilities;
  
  private IncrementalSubscription subordinatecapabilities;
  
  private int firstobject=0;
       
  private LoggingService log;

  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService aDomainService) {
    domainService = aDomainService;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }
        
  /**
   * subscribe to tasks and programming assets
   */
  protected void setupSubscriptions() {
    log = (LoggingService)
	getBindingSite().getServiceBroker().getService(this,
	LoggingService.class, null);

    log.debug("setupSubscriptions of CapabilitiesProcessingPlugin called :"); 
    CapabilitiesObject object=new CapabilitiesObject();
	
    getBlackboardService().publishAdd(object);
	
    capabilities= (IncrementalSubscription)getBlackboardService().subscribe(new CapabilitiesPredicate());
	
    completecapabilities= (IncrementalSubscription)getBlackboardService().subscribe(new CompleteCapabilitiesPredicate() );
    
   subordinatecapabilities=(IncrementalSubscription)getBlackboardService().subscribe(new ConsolidatedCapabilitiesPredicate()); 
    //getBlackboardService().publishAdd(object);
    //published=true

  }


  /**
   * Top level plugin execute loop.  
   */
  protected void execute () {
    // process unallocated tasks
    log.debug("  execute of Capabilities processing plugin called @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
    Event event=null;
    RegistrationAlert registration=null;
    CapabilitiesObject capabilitiesobject=null;
    Collection  capabilities_col=completecapabilities.getCollection();
    ArrayList list=new ArrayList(capabilities_col);
    boolean modified=false;

    if((list==null)||(list.size()==0)){
      log.debug("No capabilities object present in capabilities processing plugin : RETURNING !!!!!!!!!!!");
      return;
    }

    if(list.size()>1) {
      log.debug(" Error Multiple capabilities  object on blackboard  CapabilitiesprocessingPlugin: :");
      log.debug("CONFUSION ......  CONFUSION!!!!!!!!!!!!! Exiting !!!!!!!!:");
      return;
	    
    }
		
    capabilitiesobject=(CapabilitiesObject)list.get(firstobject);
    Enumeration capabilities_enum = capabilities.getAddedList();
    Enumeration subordinatecapabilities_enum = subordinatecapabilities.getAddedList();
    Analyzer analyzer=null;
    String analyzer_id=null;
    /*
       Process capabilities received from within the agent
     */
    while(capabilities_enum.hasMoreElements()){
      event=( Event)  capabilities_enum.nextElement();
      registration=(RegistrationAlert)event.getEvent();  
      analyzer=registration.getAnalyzer();
      analyzer_id=analyzer.getAnalyzerid();
      log.debug(" Got analyzer id #####################"+ analyzer_id );

      if(capabilitiesobject.containsKey(analyzer_id)) {
	log.debug("Analyzer is registered. registering Analyzer again :" + analyzer_id );
	RegistrationAlert existingregistartion=(RegistrationAlert)capabilitiesobject.get(analyzer_id);
	if(registration.getOperation_type()==IdmefMessageFactory.addtoregistration)  {
	  log.debug(" registration type is add");
	  // printConsolidation(existingregistartion.getClassifications(),"!!!!!before  adding add reg object"); 
	  //printConsolidation(registration.getClassifications(),"!!!!!New  add reg object"); 
	  existingregistartion= addtoRegistartion(existingregistartion,registration);
	  //printConsolidation(existingregistartion.getClassifications(),"After adding add reg object"); 
	  //capabilitiesobject.put(analyzer_id,registration);
		     
	}
	if(registration.getOperation_type()==IdmefMessageFactory.removefromregistration)  {
	     log.debug(" registration type is remove");
	     // printConsolidation(existingregistartion.getClassifications(),"!!!!!before removing  remove reg object"); 
	     //printConsolidation(registration.getClassifications(),"!!!!!New remove  reg object"); 
	     existingregistartion= removefromRegistartion(existingregistartion,registration); 
	     // printConsolidation(existingregistartion.getClassifications(),"After removing remove reg object");
	     // existingregistartion= removefromRegistartion(existingregistartion,registration); 
	}

	modified=true;
	capabilitiesobject.put(analyzer_id,existingregistartion);
      }
      else {
	log.debug("Analyzer is not yet registered. registering Analyzer:" + analyzer_id);
	modified=true;
	//printConsolidation(registration.getClassifications(),"!!!!!Classification before reg first time @@@@"); 
	capabilitiesobject.put(analyzer_id,registration);
		   
      }

    }
    if(modified) {
      log.debug(" CAPABILITIES object is modified publishing change:");
      getBlackboardService().publishChange(capabilitiesobject);
    }
    /*
       Process capabilities received from subordinate agent 
     */
    ConsolidatedCapabilities consolidatedcapabilities;
    while(subordinatecapabilities_enum.hasMoreElements())  {
      event=( Event)  subordinatecapabilities_enum.nextElement();
      consolidatedcapabilities=(ConsolidatedCapabilities)event.getEvent(); 
      /*
	Not sure what to get .. Should we do ClusterIdentifier.toString() or ClusterIdentifier.toAddress()
      */
      String agent_id= event.getSource().toAddress();
      /*
	Currently on receiving Consolidatecapabilities from subordinate agent it just prints to the screen
      */
      if(capabilitiesobject.containsKey(agent_id)) {
	log.debug(" Agent is already registered :");
      }
      else {
	log.debug(" Agent is not  registered :");
      }
    } 
	
  }


  public void printConsolidation(Classification[] classifications, String msg) {
    log.debug(msg);
    Classification classification=null;
    for(int i=0;i<classifications.length;i++){
      classification= classifications[i];
      converttoString( classification);
    }
  }

    
  public void converttoString(Classification classification) {
    log.debug(" Classification origin :"+classification.getOrigin());
    log.debug(" Classification Name :"+classification.getName());
    log.debug(" Classification URL :"+classification.getUrl());
  }


  public RegistrationAlert addtoRegistartion(RegistrationAlert existingregObject,RegistrationAlert newregobject) {
	
    Classification [] existingClassifications=existingregObject.getClassifications();
    Source[] existingSources=existingregObject.getSources();
    Target[]existingTargets=existingregObject.getTargets();
    AdditionalData[] existingData=existingregObject.getAdditionalData();
    Classification[] classifications=newregobject.getClassifications();
    Source[] sources=newregobject.getSources();
    Target[] targets=newregobject.getTargets();
    AdditionalData[]data=newregobject.getAdditionalData();
    int existinglength=existingClassifications.length;
    int newlength=classifications.length;
    if(classifications!=null) {
      Classification[] updatedclassification=new Classification[existinglength +newlength];
      System.arraycopy(existingClassifications,0,updatedclassification,0,existinglength);
      System.arraycopy(classifications,0,updatedclassification,existinglength,newlength);
      existingregObject.setClassifications(updatedclassification);
	   
    }

    if(sources!=null) {
      existinglength=existingSources.length;
      newlength=sources.length;
      Source[] updatedsources=new Source[existinglength +newlength];
      System.arraycopy(existingSources,0,updatedsources,0,existinglength);
      System.arraycopy(sources,0,updatedsources,existinglength,newlength);
      existingregObject.setSources(updatedsources);
	    
    }

    if(targets!=null) {
      existinglength=existingTargets.length;
      newlength=targets.length;
      Target[] updatedtargets=new Target[existinglength +newlength];
      System.arraycopy(existingTargets,0,updatedtargets,0,existinglength);
      System.arraycopy(targets,0,updatedtargets,existinglength,newlength);
      existingregObject.setTargets(updatedtargets); 
	    
    }

    if(data!=null) {
	    
    }

    return existingregObject;
	
  }

 
    public RegistrationAlert removefromRegistartion(RegistrationAlert existingregObject,RegistrationAlert newregobject) {
	Classification [] existingClassifications=existingregObject.getClassifications();
	Source[] existingSources=existingregObject.getSources();
	Target[]existingTargets=existingregObject.getTargets();
	AdditionalData[] existingData=existingregObject.getAdditionalData();
	Classification[] classifications=newregobject.getClassifications();
	Source[] sources=newregobject.getSources();
	Target[] targets=newregobject.getTargets();
	AdditionalData[]data=newregobject.getAdditionalData();
	int existinglength=existingClassifications.length;
	int newlength=classifications.length;
	if(classifications!=null){
	    
	  //log.debug("classifications is not null !!!!!!!!!!");
	     Classification newclassification=null;
	     Classification existingclassification=null;
	     Vector modifiedclassification=new Vector();
	     boolean found= false;
	     int foundindex=-1;
	     for(int i=0;i<newlength;i++) {
		 newclassification=classifications[i];
		 found=false;
		 foundindex=-1;
		 for(int j=0;j<existinglength;j++) {
		     existingclassification=existingClassifications[j];
		     if(!areClassificationsEqual(existingclassification,newclassification)){
			 continue;
		     }
		     log.debug("Found classification to remove:!!!!!!!!!!!!!!!!!");
		     found=true;
		     foundindex=j;
		     break;
		 }
		 
		 if((found)&&(foundindex!=-1)) {
		     log.debug(" Found classification to remove at :"+foundindex);
		     Classification modifiedClassifications[]=new Classification[existinglength-1];
		     System.arraycopy(existingClassifications,0,modifiedClassifications,0,foundindex);
		     /* doing an array copy till the index where classification is found and skiping 
			the index where classification is found in existing classification. If the index 
			is the last one there is no need to copy the last classification */
		     if((foundindex+1)!=existinglength)
			 System.arraycopy(existingClassifications,foundindex+1,modifiedClassifications,foundindex,existinglength-1);
		     // printConsolidation(modifiedClassifications,"After removing :###########");
		     existinglength=modifiedClassifications.length;
		     existingClassifications=modifiedClassifications;
		    
		     
		 }
	     }
	     existingregObject.setClassifications(existingClassifications);
	     
	}
	if(sources!=null) {
	     existinglength=existingSources.length;
	     newlength=sources.length;
	    
	}
	if(targets!=null) {
	     existinglength=existingTargets.length;
	     newlength=targets.length;
	}
	if(data!=null) {
	    
	}
	
	return existingregObject;

    }


    public boolean areClassificationsEqual(Classification existingclassification,Classification newclassification) {
    boolean equal=false;
    /*log.debug(" Existing classification:");
    converttoString(existingclassification);
    log.debug(" new classification:");
    converttoString(newclassification);
    */
    if((existingclassification.getOrigin().trim().equals(newclassification.getOrigin().trim()))&&(existingclassification.getName().trim().equals(newclassification.getName().trim()))) {
      // log.debug(" returning true  :");
	return true;
	
    }   
    return equal;
	
    }
    

}
