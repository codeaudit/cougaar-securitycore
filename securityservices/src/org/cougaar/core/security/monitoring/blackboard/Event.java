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

import org.cougaar.core.mts.MessageAddress;

import edu.jhuapl.idmef.IDMEF_Message;

/** Event interface
 *  Monitoring & Response sensors use Event objects to signal
 *  that something happened. Event objects should be published
 *  to the blackboard.
 *  Event objects may be processed locally or may be transferred
 *  to remote entities using EventTransfer objects.
 *  If the sensor knows where to send the Event, it may publish
 *  an EventTransfer directly.
 *  
 */
public interface Event extends CmrObject
{

  /**
   * Retrieve the IDMEF message (alert or heartbeat)
   */
  public IDMEF_Message getEvent();

  /**
   * Get the name of the M&R agent that created the event.
   */
  public MessageAddress getSource();

  public org.w3c.dom.Element getXML(org.w3c.dom.Document document);  

  /**
   * Convenience methods to get a synopsis of the IDMEF message
   */
}
