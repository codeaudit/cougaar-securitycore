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

import org.cougaar.core.security.monitoring.idmef.SensorInfo;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import java.util.Enumeration;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.core.service.*;
import edu.jhuapl.idmef.*;
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;



public class DummySensor extends  ComponentPlugin  implements SensorInfo {
     private DomainService domainService = null;
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
	System.out.println("setupSubscriptions of dummy sensor called :"); 
    DomainService service=getDomainService();
	if(service==null) {
	    System.out.println(" Got service as null in CapabilitiesConsolidationPlugin :");
	    return;
	}
	CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
	IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
	DummySensor sensor=new DummySensor();
	String [] events={"POD","TCPSCAN","LOGINFAILURE"};
	String [] origins={" Classification.VENDOR_SPECIFIC"," Classification.VENDOR_SPECIFIC"," Classification.VENDOR_SPECIFIC"};
	Registration reg=imessage.createRegistration(new DummySensor(),events,origins);
	// System.out.println(" Registration object is :"+reg);
	System.out.println("factory is :"+factory.toString());
	NewEvent event=factory.newEvent(reg);
	System.out.println(" going to publish capabilities :");
	getBlackboardService().publishAdd(event);
	System.out.println("Success in publishing  capabilities :");
    }
  public String getName(){
            return "<sensor-name>";
        }
        public String getManufacturer(){
            return "<manufacturer>";
        }
        public String getModel(){
            return "<model>";
        }
        public String getVersion(){
            return "<version>";
        }
        public String getAnalyzerClass(){
            return "<class>";
        }
        
       
 protected void execute () {
	// process unallocated tasks
	

    }


}
