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

import org.cougaar.core.util.UniqueObject;

/** Event implementation
 **/
public class EventImpl
  extends UniqueObjectImpl
  implements Event
{
  private IDMEF_Message theMessage = null;
  private boolean myAcknowledged; // true if this Alert has been acted upon

  public EventImpl(IDMEF_Message aMessage)
  {
    theMessage = aMessage;
  }

  /**
   * setAcknowledged - sets boolean indicating whether alert has been
   * acknowleged.
   * 
   * @param ack boolean
   */
  public void setAcknowledged(boolean ack) {
    myAcknowledged = ack;
  }

  /**
   * getAcknowledged - returns boolean indicating whether alert has been
   * acknowledged.
   *
   * @return boolean
   */
  public boolean getAcknowledged() {
    return myAcknowledged;
  }
 

  public void setMessage(IDMEF_Message aMessage)
  {
    theMessage = aMessage;
  }

  public IDMEF_Message getMessage()
  {
    return theMessage;
  }

}
