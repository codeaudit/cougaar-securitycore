/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
 
 
 
 
 
 
 
 




package org.cougaar.core.security.access;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.policy.ThreatConLevelAsset;
import org.cougaar.core.service.DomainService;
import org.cougaar.planning.ldm.LDMServesPlugin;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.service.LDMService;

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
