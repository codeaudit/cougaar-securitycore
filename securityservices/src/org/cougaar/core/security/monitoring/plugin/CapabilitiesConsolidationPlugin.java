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

import edu.jhuapl.idmef.*;

// Cougaar core services
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.core.service.*;
import org.cougaar.core.domain.RootFactory;
import org.cougaar.core.domain.Factory;

// Cougaar security services
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.CmrObject;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CapabilitiesObject;
import org.cougaar.core.security.monitoring.idmef.*;

class ModifiedCapabilitiesPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CapabilitiesObject ) {
      System.out.println(" Got object which is  instanceof CapabilitiesObject");
      return true;
    }
    return ret;
  }
}

/**
 *
 **/
public class CapabilitiesConsolidationPlugin extends ComponentPlugin {

  // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;

  private IncrementalSubscription modifiedcapabilities;
    
  private int firstobject=0;

  
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
    System.out.println("setupSubscriptions of CapabilitiesConsolidationPlug in called :"); 
    modifiedcapabilities= (IncrementalSubscription)getBlackboardService().subscribe(new ModifiedCapabilitiesPredicate());

  }


  /**
   * Top level plugin execute loop.  
   */
  protected void execute () {
    // process unallocated tasks
    System.out.println(" Execute of CapabilitiesConsolidation Plugin called !!!!!!!!");
     DomainService service=getDomainService();
    if(service==null) {
      System.out.println(" Got service as null in Test Dummy Sensor  :");
      return;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    //Event event=null;
    Collection  modifiedcapabilities_col=modifiedcapabilities.getChangedCollection();
    ArrayList list=new ArrayList(modifiedcapabilities_col);
    
    if((list==null)||(list.size()==0)){
      System.out.println(" !!!! No modified capabilities currently present  !!!!!!! RETURNING  !!!!!!!!!!!!!!!!");
      return;
    }
    
    if(list.size()>1) {
      System.out.println(" Error Multiple complete capabilities object on blackboard in Capabilities Consolidation plugin !!!!!!!!!!!!!!!!!!! CONFUSION CONFUSION CONFUSION  RETURNIG !!!!!!!:");
      return;
    }

    ConsolidatedCapabilities consCapabilities=null;
    CapabilitiesObject capabilitiesobject=null;
    capabilitiesobject=(CapabilitiesObject )list.get(firstobject);
    consCapabilities=createConsolidatedCapabilities();
    RegistrationAlert registration=null;
    Classification consclassifications[]=consCapabilities.getClassifications();
    Classification regclassifications[]=null;
    Enumeration keys=capabilitiesobject.keys();
    String key=null;
	
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      System.out.println(" KEY IN CAPABILITIES OBJECT IS :"+key);
      registration=(RegistrationAlert)capabilitiesobject.get(key);
      regclassifications=registration.getClassifications();
      if(consclassifications==null){
	//System.out.println("consclassifications was null Creating one :"); 
	consclassifications=new Classification[regclassifications.length];
	System.arraycopy(regclassifications,0,consclassifications,0,regclassifications.length);
	//printConsolidation(consclassifications," First one added after creating cons obj:");
      }
      else {
	//System.out.println("consclassifications was NOT NULL Consolidating !!!!!!!!!! :"); 
	//printConsolidation(consclassifications," Already cons obj present before adding new %%%%%%%%%%%%%%%% :");
	consclassifications=getConsolidatedClassification(regclassifications,consclassifications);
	//printConsolidation(consclassifications," Already cons obj present added new $$$$$$$$$$$$$$$$$$ :");
      }
	    
    }
    consCapabilities.setClassifications(consclassifications);
    System.out.println(" consolidated classification is :");
    consclassifications=consCapabilities.getClassifications();
    printConsolidation(consclassifications," consolidated classification after processing is :");
    //converttoString(consclassifications);
    /*
      currently have commented the below code as Capabilities processing plugin has also subscribed to it and it will 
      get into loop.
     
     NewEvent event=factory.newEvent(consCapabilities);
     getBlackboardService().publishAdd(event);
    */
  }


  public ConsolidatedCapabilities createConsolidatedCapabilities() {
    DomainService service=getDomainService();
    if(service==null) {
      System.out.println(" Got service as null in CapabilitiesConsolidationPlugin :");
      return null;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    ConsolidatedCapabilities conscapabilities=imessage.createConsolidatedCapabilities();
    return conscapabilities;
  }

    
  public void printConsolidation(Classification[] classifications, String msg) {
    System.out.println(msg);
    Classification classification=null;
    for(int i=0;i<classifications.length;i++){
      classification= classifications[i];
      converttoString( classification);
    }
  }

   
  public Classification[] getConsolidatedClassification( Classification[] newcapabilities ,Classification[] existingcapabilities ) {

    //Arrays.sort((Object[])existingcapabilities);
    printConsolidation(newcapabilities,"New Capabilities:");
    printConsolidation(existingcapabilities,"Existing  Capabilities:");
    Vector indexes=new Vector();
    Classification existingclas=null;
    Classification newclas=null;
    int index=-1;
    boolean found=false;
    for(int i=0;i<newcapabilities.length;i++){
      found=false;
      newclas=newcapabilities[i];
      for(int j=0;j<existingcapabilities.length;j++) {
	existingclas=existingcapabilities[j];
	if(!areClassificationsEqual(existingclas,newclas)) {
	  continue;
	}
		
	found=true;
	break;
		
      }
      if(!found) {
	System.out.println(" new  capabilities :");
	converttoString(newclas);
	indexes.add(newclas);
      }
	   
    }
    Classification[] consolidate=new Classification[existingcapabilities.length+indexes.size()];
    Classification clas=null;
    System.arraycopy(existingcapabilities,0,consolidate,0,existingcapabilities.length);
    index=existingcapabilities.length;
    for(int i=0;i<indexes.size();i++){
      clas = (Classification) indexes.elementAt(i);
      consolidate[i+index]=clas;
      // System.out.println("New Classifications are :"+clas.toString());
    }
    return consolidate;
  }

  public boolean areClassificationsEqual(Classification existingclassification,Classification newclassification) {
    boolean equal=false;
    if((existingclassification.getOrigin().trim().equals(newclassification.getOrigin().trim()))&&(existingclassification.getName().trim().equals(newclassification.getName().trim()))) {
      return true;
    }
    return equal;
	
  }
    
  public void converttoString(Classification classification) {
    System.out.println(" Classification origin :"+classification.getOrigin());
    System.out.println(" Classification Name :"+classification.getName());
    System.out.println(" Classification URL :"+classification.getUrl());
  }
    
}

