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

import org.cougaar.core.blackboard.*;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.*;
import org.cougaar.core.service.DomainService;
import org.cougaar.planning.ldm.policy.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.planning.ldm.LDMServesPlugin;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.service.LDMService;
import org.cougaar.util.*;

import org.cougaar.core.security.policy.*;

/**
 * Creates and publishes a threat con level object so 
 * the cougaar-aware proxy can be informed of the society's current
 * threat con level.
 */
public class AssetCreationPlugin extends ComponentPlugin {

    protected void setupSubscriptions(){
        ServiceBroker sb = getServiceBroker();
        DomainService ds = (DomainService)sb.getService(this, DomainService.class, null);
        PlanningFactory pf = (PlanningFactory)ds.getFactory(PlanningFactory.class);
        LDMService ldms = (LDMService)sb.getService(this, LDMService.class, null); 
        LDMServesPlugin ldm = ldms.getLDM();
        ThreatConLevelAsset threatConLevelPrototype = 
	    (ThreatConLevelAsset)pf.createPrototype
	    (ThreatConLevelAsset.class, "tcl");
        ldm.cachePrototype("tcl", threatConLevelPrototype);
        threatConLevelPrototype.setThreatConLevel(3);
        getBlackboardService().publishAdd(threatConLevelPrototype);
    }

    /**
     * this method should never be called but it is defined here to conform
     * to the interface...
     */
    protected void execute(){  }

}
