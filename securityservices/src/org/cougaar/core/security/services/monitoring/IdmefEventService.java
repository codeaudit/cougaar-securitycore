/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */

package org.cougaar.core.security.services.monitoring;

// Cougaar core services
import org.cougaar.core.component.Service;

import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Heartbeat;

/** IDMEF event service.
 *
 *  This service must be used by all M&R components that generate
 *  IDMEF messages. M&R components should never call an IDMEF library
 *  directly.
 *
 *  The default implementation of this service will return standard
 *  Cougaar IDMEF messages (e.g. setting fields such as CreationTime).
 *
 *  Specialized implementations should provide more details.
 *  For example, an implementation may provide detailed information
 *  about a rogue agent attacking another agent.
 *  
 */
public interface IdmefEventService
  extends Service
{
  /** Create an IDMEF Alert message.
   *  This method returns a new Alert message. Upon returning the Alert,
   *  a component is free to add more detailed attributes.
   *  @return - an IDMEF Alert message
   */
  public Alert createAlert();

  /** Create an IDMEF Heartbeat message.
   *  This method returns a new Heartbeat message. Upon returning the
   *  Heartbeat, a component is free to add more detailed attributes.
   *  @return - a Heartbeat IDMEF message
   */
  public Heartbeat createHeartbeat();

}
