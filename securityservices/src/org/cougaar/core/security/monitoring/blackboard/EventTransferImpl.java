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

package org.cougaar.core.security.monitoring.plan;

import edu.jhuapl.idmef.IDMEF_Message;

import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.planning.ldm.asset.Asset;

/** EventTransferImpl
 */
public class EventTransferImpl 
  extends UniqueObjectImpl
  implements EventTransfer
{

  private Event theEvent;
  private Asset assigneeAsset;
  private ClusterIdentifier assignerCluster;

  /** 
   * @param aEvent  The event being transferred
   * @param to  The agent that will receive this event for use
   * @param from  The agent that is provided this event for use
   */

  public EventTransferImpl(Event aEvent, Asset to, ClusterIdentifier from)
  {
    setEvent(aEvent);
    setAssignee(to);
    setAssignor(from);
  }

  /** Returns a Monitoring & Response Event.
   * This Event is being assigned to an agent for use.
   *
   * @return Event - a Monitoring & Response Event
   */
		
  public Event getEvent() {
    return theEvent;
  }
 	
  /** Returns the Asset to which the asset is being assigned.
   * @return Asset representing the destination asset
   */
  public Asset getAssignee()
  {
    return assigneeAsset;
  }
 
  /** Returns the Cluster from which the asset was assigned.
   * @return ClusterIdentifier representing the source of the asset
   */
 	
  public ClusterIdentifier getAssignor()
  {
    return assignerCluster;
  }

  /**
   * @param toAsset - Set the Asset being assigned the Asset
   */
  private void setAssignee(Asset toAsset) {
    assigneeAsset = toAsset;
  }
  
  /** Sets the Cluster that the asset is assigned from.
   * @param aCluster
   */
 	
  private void setAssignor(ClusterIdentifier aCluster) {
    assignerCluster = aCluster;
  }

  private void setEvent(Event aEvent)
  {
    theEvent = aEvent;
  }
}





