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

import org.cougaar.core.util.UID;
import org.cougaar.planning.ldm.asset.Asset;

/** EventTransferImpl
 */
public class EventTransferImpl
  extends EventImpl
  implements NewEventTransfer
{
  private Asset targetAsset;

  public EventTransferImpl(UID aUID)
  {
    super(aUID);
  }

  /** 
   * @param aEvent  The event being transferred
   * @param to  The agent that will receive this event for use
   * @param from  The agent that is provided this event for use
   */
  public EventTransferImpl(UID aUID,
			   Asset aTarget,
			   Event aEvent)
  {
    super(aUID, aEvent.getSource(), aEvent.getEvent());
    setTarget(aTarget);
  }

  /** ******************************************************************
   *  EventTransfer interface
   */

  public Asset getTarget()
  {
    return targetAsset;
  }
 
  public void setTarget(Asset toAsset) {
    targetAsset = toAsset;
  }

  /** ******************************************************************
   *
   */

  public String toString() {
    String s = "";
    if (getSource() != null) {
      s = s + getSource().toString() + "->";
    }
    if (getTarget() != null) {
      s = s + getTarget().toString() + "/";
    }
    if (getEvent() != null) {
      s = s + getEvent().toString();
    }
    return s;
  }

}





