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

import org.cougaar.core.util.UniqueObject;
import org.cougaar.planning.ldm.asset.Asset;
import org.cougaar.core.agent.ClusterIdentifier;

/** NewEventTransfer interface. See Event class description.
 *  An EventTransfer logic provider is responsible for
 *  sending EventTransfer objects to remote agents.
 */
public interface NewEventTransfer
  extends CmrObject, EventTransfer
{

  /** Set a Monitoring & Response Event.
   * This Event is being assigned to an agent for use.
   *
   * @param Event - a Monitoring & Response Event
   */
  public void setEvent(Event aEvent);

  /** Set the Asset to which the asset is being assigned.
   * @param Asset representing the destination asset
   */
  public void setAssignee(Asset toAsset);
 
  /** Set the Cluster from which the asset was assigned.
   * @param ClusterIdentifier representing the source of the asset
   */
  public void setAssignor(ClusterIdentifier aCluster);
}
