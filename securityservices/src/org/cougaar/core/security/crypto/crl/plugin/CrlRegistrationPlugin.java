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

package org.cougaar.core.security.crypto.crl.plugin;


import java.util.*;
// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.*;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.multicast.AttributeBasedAddress;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.core.util.UID;
import org.cougaar.core.service.community.*;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceAvailableEvent;

import org.cougaar.core.security.crypto.crl.blackboard.*;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.multicast.AttributeBasedAddress;



public class CrlRegistrationPlugin extends ComponentPlugin {

  // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;
  private IncrementalSubscription crlregistration;
  private LoggingService loggingService=null;
  private Vector messageAddress=new Vector();
  private boolean readcomplete=true;
  private boolean readyforreg=false;
  class CRLRegistrationPredicate implements UnaryPredicate{
    public boolean execute(Object o) {
      boolean ret = false;
      if (o instanceof  CRLRegistration ) {
	return true;
      }
      return ret;
    }
  }
  
  
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

  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;
    Iterator iter=l.iterator();
    String address=null;
    while(iter.hasNext()) {
      address=(String)iter.next();
      messageAddress.add(address);
      if(loggingService!=null) {
	loggingService.debug(" messageAddress added:"+ address);
      }
    }
    
  }
  protected void setupSubscriptions() {
    loggingService = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
        
    crlregistration=(IncrementalSubscription)getBlackboardService().subscribe
      (new CRLRegistrationPredicate());
    
  }
  
  protected void execute () {
    loggingService.debug("Execute of crl registration  plugin called :");
    for(int j=0;j<messageAddress.size();j++){
      loggingService.debug((String)messageAddress.elementAt(j));
    }
    Iterator regiterator=null;
    Collection regcolleaction=null;
    CrlManagementService crlmgmtservice=(CrlManagementService)
      getServiceBroker().getService(this, 
				    CrlManagementService.class, 
				    null);
    if(crlmgmtservice==null){
      loggingService.debug(" crlmgmtservice service is null");
    }
    
    if(crlmgmtservice!=null) {
      if(readcomplete) {
	regcolleaction= crlregistration.getCollection();
	readcomplete=false;
      }
      else {
	regcolleaction= crlregistration.getAddedCollection();
      }
    }
    else {
      loggingService.debug("crlmgmtservice is null cannot register :");
    }
        
    regiterator=regcolleaction.iterator();
    CRLRegistration crlregistartion=null;
    CRLAgentRegistration crlagentregistartion=null;
    CrlRelay crlregrelay=null;
    if(crlmgmtservice!=null) {
      while(regiterator.hasNext()) {
	crlregistartion=(CRLRegistration)regiterator.next();
	crlagentregistartion=new CRLAgentRegistration(crlregistartion.dnName,
						      crlregistartion.ldapURL,
						      crlregistartion.ldapType);
	 
	for(int i=0;i<messageAddress.size();i++){
	  crlregrelay=crlmgmtservice.newCrlRelay(crlagentregistartion,
						 new ClusterIdentifier(((String)messageAddress.elementAt(i)).trim()));
	  loggingService.debug("Sending CRL Registaration message :"+crlregistartion.dnName);
	   
	  getBlackboardService().publishAdd(crlregrelay);
	}
      }
    }
    else {
      loggingService.debug("crlmgmtservice is null cannot register :"+crlregistartion.dnName);
    }
       
        
  }
  
  public void publishCrlRregistration() {
    Iterator regiterator=null;
    Collection regcolleaction=null;
    CrlManagementService crlmgmtservice=(CrlManagementService)
      getServiceBroker().getService(this, CrlManagementService.class, null);
    regcolleaction=crlregistration.getCollection();
    CRLRegistration crlregistartion=null;
    CRLAgentRegistration crlagentregistartion=null;
    CrlRelay crlregrelay=null;
    if(crlmgmtservice!=null) {  
      getBlackboardService().openTransaction();
      while(regiterator.hasNext()) {
	crlregistartion=(CRLRegistration)regiterator.next();
	crlagentregistartion=new CRLAgentRegistration(crlregistartion.dnName,
						      crlregistartion.ldapURL,
						      crlregistartion.ldapType);
	  
	for(int i=0;i<messageAddress.size();i++){
	  crlregrelay=crlmgmtservice.newCrlRelay(crlagentregistartion,
						 new MessageAddress((String)messageAddress.elementAt(i)));
	  loggingService.debug("Sending CRL Registaration message :"+crlregistartion.dnName);
	    
	  getBlackboardService().publishAdd(crlregrelay);
	}
	  
      }
      getBlackboardService().closeTransaction();
    }
    else {

      loggingService.debug("crlmgmtservice is null cannot register :"+crlregistartion.dnName);
    }
      
         
  }
  
  private class CrlManagementServiceAvailableListener implements ServiceAvailableListener
  {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      CrlManagementService crlMgmtService =null;
      //ServiceProvider newSP = null;
      Class sc = ae.getService();
      if( CrlManagementService.class.isAssignableFrom(sc)) {
	crlMgmtService = (CrlManagementService) getServiceBroker().getService(this,CrlManagementService.class, null);
	loggingService.info("crlMgmt Service is available now in AgentRegistration Plugin");
      }
      if(crlMgmtService!=null){
	publishCrlRregistration();
      }
      
    }
  } 

}
