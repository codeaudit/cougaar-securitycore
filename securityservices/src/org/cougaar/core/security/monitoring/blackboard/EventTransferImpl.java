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
import org.cougaar.core.util.UniqueObject;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.planning.ldm.asset.Asset;
import org.cougaar.core.util.UID;
import org.cougaar.core.blackboard.Publishable;

/** EventTransferImpl
 */
public class EventTransferImpl 
  implements NewEventTransfer, UniqueObject, Publishable
{

  private UID myUID;
  private Event theEvent;
  private Asset assigneeAsset;
  private ClusterIdentifier assignerCluster;

  /** 
   * @param aEvent  The event being transferred
   * @param to  The agent that will receive this event for use
   * @param from  The agent that is provided this event for use
   */

  public EventTransferImpl(Event aEvent,
			   UID aUID,
			   Asset to, ClusterIdentifier from)
  {
    setEvent(aEvent);
    setAssignee(to);
    setAssignor(from);
    setUID(aUID);
  }

  public EventTransferImpl(UID aUID)
  {
    setUID(aUID);
  }
  public EventTransferImpl(UID aUID, ClusterIdentifier aSource)
  {
    setUID(aUID);
    setAssignor(aSource);
  }

  /** ******************************************************************
   *  EventTransfer interface
   */

  /** Returns a Monitoring & Response Event.
   * This Event is being assigned to an agent for use.
   *
   * @return Event - a Monitoring & Response Event
   */
		
  public Event getEvent() {
    return theEvent;
  }

  public void setEvent(Event aEvent)
  {
    theEvent = aEvent;
  }
 	
  public Asset getAssignee()
  {
    return assigneeAsset;
  }
 
  public ClusterIdentifier getAssignor()
  {
    return assignerCluster;
  }

  public void setAssignee(Asset toAsset) {
    assigneeAsset = toAsset;
  }
  
  public void setAssignor(ClusterIdentifier aCluster) {
    assignerCluster = aCluster;
  }
  /** ******************************************************************
   *  UniqueObject interface
   */

  /**
   * setUID - set uid for the object
   *
   * @param uid UID assigned to object
   */
  public void setUID(UID uid) {
    myUID = uid;
  }
  
  /**
   * getUID - get uid for the object
   *
   * @return UID assigned to object
   */
  public UID getUID() { 
    return myUID;
  }

  /** ******************************************************************
   *  Publishable interface
   */

  public boolean isPersistable() {
    return true;
  }

  /** ******************************************************************
   *
   */

  public String toString() {
    String s = "";
    if (getAssignor() != null) {
      s = s + getAssignor().toString() + "->";
    }
    if (getAssignee() != null) {
      s = s + getAssignee().toString() + "/";
    }
    Event e = getEvent();
    if (e != null) {
      s = s + e.toString();
    }
    return s;
  }

}





