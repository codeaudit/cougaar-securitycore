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
import java.security.cert.X509CRL;

//Cougaar 
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.*;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.multicast.AttributeBasedAddress;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.core.mts.MessageAddress;

//Security services
import  org.cougaar.core.security.services.crypto.CRLCacheService;
import  org.cougaar.core.security.crypto.crl.blackboard.*;
import  org.cougaar.core.security.crypto.CRLWrapper;

public class CrlResponsePlugin  extends ComponentPlugin {

  private DomainService domainService = null;
  private IncrementalSubscription crlresponse;
  private LoggingService loggingService=null;
  
  class CrlResponsePredicate implements UnaryPredicate{
    public boolean execute(Object o) {
      boolean ret = false;
      CrlRelay relay=null;
      if (o instanceof  CrlRelay ) {
	relay=(CrlRelay)o;
	if(relay.getResponse()!=null) {
	  return true;
	}
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

  protected void setupSubscriptions() {
    loggingService = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
     
    crlresponse=(IncrementalSubscription)getBlackboardService().subscribe
      (new CrlResponsePredicate());
        
  }
  
  protected void execute () {
    Iterator iter=null;
    CRLCacheService crlcacheService=null;
    crlcacheService=(CRLCacheService)getBindingSite().getServiceBroker().getService
      (this, CRLCacheService.class, null);
    Collection crlCollection=crlresponse.getChangedCollection();
    iter=crlCollection.iterator();
    CRLWrapper receivedcrl=null;
    CrlRelay relay=null;
    String dn=null;
    loggingService.debug("Received response for crl update:");
    while(iter.hasNext()) {
      relay=(CrlRelay)iter.next();
      if(relay.getResponse()!=null) {
	receivedcrl=(CRLWrapper) relay.getResponse();
	dn=receivedcrl.getDN();
	loggingService.debug("Received response for crl update for DN :"+ dn);
	Date currentLastmodified=getDateFromUTC(receivedcrl.getLastModifiedTimestamp());
	Date cacheLastModified=getDateFromUTC(crlcacheService.getLastModifiedTime(dn));

	loggingService.debug("Received Crl last modified date ="+currentLastmodified.toString());
	if(cacheLastModified!=null)
	  loggingService.debug(" Crl cache last modified date ="+cacheLastModified.toString());
	if(cacheLastModified!=null) {
	  if(currentLastmodified.after(cacheLastModified)) {
	    loggingService.debug("Updating CRL Cache for DN :"+ dn);
	    crlcacheService.updateCRLCache(receivedcrl);
	  }
	  else {
	    loggingService.debug("Received dates are equal in response plugin:");
	  }
	}
	else{
	  loggingService.debug("Updating CRL Cache for DN :"+ dn);
	  crlcacheService.updateCRLCache(receivedcrl);
	}
      }
      else{
	loggingService.debug("Received response for crl update but response was null:");
      }
    }
    loggingService.debug("execute of CRL Response Plugin Done :");
  }
   
  private Date getDateFromUTC( String utc ) {
    // utc is in the form of "20010706080000Z". get year,
    // month, day, hour, minute, and second from the utc
    if(utc==null) {
      loggingService.debug("utc is null :");
      return null;
      //Calendar utcTime = Calendar.getInstance();
      //return utcTime.getTime();
    }
    TimeZone tz = TimeZone.getTimeZone("GMT");
    int year   = Integer.parseInt( utc.substring(  0, 4  ));
    int mon    = Integer.parseInt( utc.substring(  4, 6  ));
    int day    = Integer.parseInt( utc.substring(  6, 8  ));
    int hour   = Integer.parseInt( utc.substring(  8, 10 ));
    int minute = Integer.parseInt( utc.substring( 10, 12 ));
    int second = Integer.parseInt( utc.substring( 12, 14 ));
    
    Calendar utcTime = Calendar.getInstance(tz);
    // set calendar to the time
    utcTime.set( year, mon-1 , day, hour, minute, second );
    return utcTime.getTime();
  }
  
}
