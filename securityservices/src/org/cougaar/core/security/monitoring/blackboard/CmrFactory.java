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

package org.cougaar.core.security.monitoring.blackboard;

import edu.jhuapl.idmef.IDMEF_Message;

// Cougaar core services
import org.cougaar.core.domain.Factory;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.UIDServer;
import org.cougaar.core.util.UID;
import org.cougaar.planning.ldm.asset.Asset;
import org.cougaar.planning.ldm.LDMServesPlugin;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;


public class CmrFactory
  implements Factory
{
  protected MessageAddress selfClusterId;
  protected UIDServer myUIDServer;
  private  IdmefMessageFactory idmefmessagefactory;

  private ServiceBroker serviceBroker;

  /**
   * Constructor for use by domain specific Factories
   * extending this class
   */
  public CmrFactory() { }
  // change the input parameter to an agent id service and uid service or just service broker
  public CmrFactory(LDMServesPlugin ldm) {
    // Attach our factory to the M&R factory
    PlanningFactory pf = ldm.getFactory();
	
    /*
      See org.cougaar.tools.csmart.runtime.ldm.CSMARTFactory for
      an example of what to add here.
      pf.addAssetFactory(
      new org.cougaar.tools.csmart.runtime.ldm.asset.AssetFactory());
      pf.addPropertyGroupFactory(
      new org.cougaar.tools.csmart.runtime.ldm.asset.PropertyGroupFactory());
    */
    selfClusterId = ldm.getMessageAddress();
    myUIDServer = ldm.getUIDServer();
    idmefmessagefactory=new IdmefMessageFactory(ldm);

  }
  
  /**
   * @return a new <code>UID</code>
   */
  public UID getNextUID() {
    return myUIDServer.nextUID();
  }

  public NewEvent newEvent(IDMEF_Message aMessage) {
    return new EventImpl(getNextUID(),
        selfClusterId,
        aMessage);
  }
 
  public NewEventTransfer newEventTransfer(Event event,
      Asset target) {
    return new EventTransferImpl(getNextUID(),
        target,
        event);
  }
  public IdmefMessageFactory getIdmefMessageFactory(){
    return idmefmessagefactory;
  }
    
  public CmrRelay newCmrRelay(Event event, MessageAddress dest) {
    CmrRelay relay = new CmrRelay(getNextUID(), selfClusterId, dest, event, null);
    return relay;
  }
  
  public CmrRelay newCmrRelay(Object event, MessageAddress dest) {
    CmrRelay relay = new CmrRelay(getNextUID(), selfClusterId, dest, event,null);
    return relay;
  }
 
}
