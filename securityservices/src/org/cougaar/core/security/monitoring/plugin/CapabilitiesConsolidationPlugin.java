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

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import java.util.Enumeration;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.core.service.*;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Alert;
import org.cougaar.core.component.ServiceRevokedListener;
import org.cougaar.core.component.ServiceRevokedEvent;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.domain.RootFactory;
import org.cougaar.core.domain.Factory;
import org.cougaar.core.security.monitoring.blackboard.CmrObject;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.idmef.Registration;

/**
 * A predicate that matches all "CMR object with capabilities registration "
 */
class CapabilitiesPredicate implements UnaryPredicate{
    public boolean execute(Object o) {
	boolean ret = false;
	if (o instanceof CmrObject ) {
	    System.out.println(" Got object which is  instanceof CmrObject");
	    if(o instanceof Event){
		Event e=(Event)o;
		IDMEF_Message msg=e.getEvent();
		if(msg instanceof Registration){
		    return true;
		}
	    }
	    else {
		 System.out.println(" Got object which is not  instanceof Event");
	    }
	}
	else {
	    System.out.println(" Got object which is not instanceof CmrObject");
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

    private IncrementalSubscription capabilities;
 

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
	System.out.println("setupSubscriptions of CapabilitiesConsolidationPlugin called :"); 
	capabilities= (IncrementalSubscription)getBlackboardService().subscribe                                                 (new CapabilitiesPredicate());
		
    }


    /**
     * Top level plugin execute loop.  
     */
    protected void execute () {
	// process unallocated tasks
	Event reg=null;
	Enumeration capabilities_enum = capabilities.getAddedList();
	while(capabilities_enum.hasMoreElements()){
	 reg=( Event)  capabilities_enum.nextElement();
	 System.out.println("Got registration object :"+((Registration)reg.getEvent()).getAnalyzer().getAnalyzerid());
	}

    }

}
