/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 * Created on October 22, 2001, 2:02 PM EDT
 */

package org.cougaar.core.security.access;

import java.util.*;

// Cougaar core services
import org.cougaar.util.*;
import org.cougaar.core.blackboard.*;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.mts.*;
import org.cougaar.core.persist.*;
import org.cougaar.core.component.*;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.multicast.AttributeBasedAddress;

// Cougaar security services
import org.cougaar.core.security.acl.trust.*;

/**
 * An interface to objects which guard the blackboard. 
 */
public class BlackboardAccessControlAdaptor
  implements BlackboardService, BlackboardServesLogicProvider,
  BlackboardForAgent
{
  protected BlackboardClient client;

  protected Blackboard service;

  public BlackboardAccessControlAdaptor
  (BlackboardClient client, Blackboard service) {
    this.client = client;
    this.service = service;
  }


  // BlackboardServesLogicProvider methods

  public void add(Object obj) {
    service.add(obj);
  }

  public void change(Object obj, Collection changes) {
    service.change(obj, changes);
  }
    
  public void remove(Object obj) { service.remove(obj);
  }
    
  public PublishHistory getHistory() { return service.getHistory(); }
    
  public Enumeration searchBlackboard(UnaryPredicate predicate) {
    return service.searchBlackboard(predicate);
  }

  public void sendDirective(Directive dir) { service.sendDirective(dir); }

  public void sendDirective(Directive dir, Collection changeReports) {
    service.sendDirective(dir, changeReports);
  }

  /* Uncomment when Cougaar 9.4.1 is out.
  public ABATranslation getABATranslation(AttributeBasedAddress aba) {
    return service.getABATranslation(aba);
  }
  */

  public ABATranslation getABATranslation(AttributeBasedAddress aba) {
    return service.getABATranslation(aba);
  }

  // BlackboardService methods

  public void closeTransactionDontReset() {
    service.closeTransactionDontReset();
  }

  public void closeTransaction() {
    service.closeTransaction();
  } 
 
  public void closeTransaction(boolean resetp) {
    // Method is deprecated.
    service.closeTransactionDontReset();
  }
             
  public boolean didRehydrate() { return service.didRehydrate(); }

  public int getPublishAddedCount() { 
    return service.getPublishAddedCount(); 
  }
                               
  public int getPublishChangedCount() { 
    return service.getPublishChangedCount(); 
  }
                               
  public int getPublishRemovedCount() { 
    return service.getPublishRemovedCount(); 
  }
                               
  public Subscriber getSubscriber() { return service.getSubscriber(); }
                               
  public int getSubscriptionCount() { 
    return service.getSubscriptionCount(); 
  }
                               
  public int getSubscriptionSize() { return service.getSubscriptionSize(); }
                               
  public boolean haveCollectionsChanged() 
    { 
      return service.haveCollectionsChanged(); 
    }
                
  public void openTransaction() { service.openTransaction(); }
             
  public boolean publishAdd(Object o) { return service.publishAdd(o); }
             
  public boolean publishChange(Object o) { return service.publishChange(o); }
                 
  public boolean publishChange(Object o, Collection changes) 
    { 
      return publishChange(o, changes); 
    }
                                           
  public boolean publishRemove(Object o) { return publishRemove(o); }
                               
  public Collection query(UnaryPredicate isMember) 
    { 
      return service.query(isMember); 
    }

  public SubscriptionWatcher registerInterest() 
    { 
      return service.registerInterest(); 
    }

  public SubscriptionWatcher registerInterest(SubscriptionWatcher w) 
    { 
      return service.registerInterest(w); 
    }
                
  public void setReadyToPersist()  { service.setReadyToPersist(); }
                
  public void setShouldBePersisted(boolean value) 
    { 
      service.setShouldBePersisted(value); 
    }
             
  public boolean shouldBePersisted() { return service.shouldBePersisted(); }
                                                                      
  public void signalClientActivity() 
    { 
      service.signalClientActivity(); 
    }

  public Subscription subscribe(Subscription s) {
    return service.subscribe(s);
  }

  public Subscription subscribe(UnaryPredicate isMember) { 
    return service.subscribe(isMember);  
  }
         
  public Subscription subscribe(UnaryPredicate isMember, boolean isIncremental)  {
    return service.subscribe(isMember, isIncremental);   
  }
         
  public Subscription subscribe(UnaryPredicate isMember, 
				Collection realCollection) {
    return service.subscribe(isMember, realCollection);
  }
         
        
  public Subscription subscribe(UnaryPredicate isMember, 
				Collection realCollection, 
				boolean isIncremental) {
    return service.subscribe(isMember, realCollection,isIncremental);
  }
             
  public boolean tryOpenTransaction() {
    return service.tryOpenTransaction();
  }                         
                
  public void unregisterInterest(SubscriptionWatcher w) { 
    service.unregisterInterest(w); 
  }
    
  public void unsubscribe(Subscription subscription) { 
    service.unsubscribe(subscription); 
  }

  public void persistNow() throws PersistenceNotEnabledException {
    service.persistNow();
  }

  // BlackboardForAgent Methods

  /**
   * Process a list of messages from the distributor. 
   */
  public void receiveMessages(List messages)
    {
      Directive[] directive = null;
      TrustSet[] trustSet = null;
      Iterator it = messages.iterator();
      while(it.hasNext()) {
	Message msg = (Message)it.next();
	if(msg instanceof Message) {
	  if(msg instanceof DirectiveMessage) {
	    directive =  ((DirectiveMessage)msg).getDirectives();
//		   trustSet =  ((DirectiveMessage)msg).getTrustSets();
	    for(int minor = 0; minor < directive.length; minor++) {
	      // add trust attributes from each directive here
	      //trustService.add(directive[minor], trustSet[minor]);
	    } 
	  }
	  else { // add trust attributes to the trust service
		    
	  }
	}
      }
      service.receiveMessages(messages);
    }

  public Persistence getPersistence() 
    {
      return null;		// this will break but we need it to compile
      //return service.getPersistence();
    }    

  //
  // This method in the BlackboardForAgent interface is new in 8.6.2.
  // This is a stub implementation.
  //
  public void restartAgent(ClusterIdentifier cid) {
    System.err.println("WARNING: org.cougaar.core.security.access.BlackboardAccessControlAdapter.restartAgent() not implemented. cid="+cid);
  }
}
