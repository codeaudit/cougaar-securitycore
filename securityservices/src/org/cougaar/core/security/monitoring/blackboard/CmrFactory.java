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

// Cougaar core services
import org.cougaar.core.domain.Factory;
import org.cougaar.core.agent.ClusterContext;
import org.cougaar.core.agent.ClusterServesPlugin;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.core.service.UIDServer;
import org.cougaar.core.util.UID;
import org.cougaar.core.domain.RootFactory;
import org.cougaar.core.domain.LDMServesPlugin;

public class CmrFactory
  implements Factory
{
  protected ClusterIdentifier selfClusterId;
  protected UIDServer myUIDServer;

  /**
   * Constructor for use by domain specific Factories
   * extending this class
   */
  public CmrFactory() { }

  public CmrFactory(LDMServesPlugin ldm) {
    // Attach our factory to the M&R factory
    RootFactory rf = ldm.getFactory();

    /*
      See org.cougaar.tools.csmart.runtime.ldm.CSMARTFactory for
      an example of what to add here.
      rf.addAssetFactory(
      new org.cougaar.tools.csmart.runtime.ldm.asset.AssetFactory());
      rf.addPropertyGroupFactory(
      new org.cougaar.tools.csmart.runtime.ldm.asset.PropertyGroupFactory());
    */
    ClusterServesPlugin cspi = (ClusterServesPlugin)ldm;
    selfClusterId = cspi.getClusterIdentifier();
    myUIDServer = ((ClusterContext)ldm).getUIDServer();

  }
  
  /**
   * @return a new <code>UID</code>
   */
  public UID getNextUID() {
    return myUIDServer.nextUID();
  }

  public NewEvent newEvent() {
    return new EventImpl(getNextUID(), selfClusterId);
  }

  public NewEventTransfer newEventTransfer() {
    return new EventTransferImpl(getNextUID(), selfClusterId);
  }
}
