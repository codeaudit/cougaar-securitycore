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

package org.cougaar.core.security.crypto.crl;


// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.crypto.crl.blackboard.CrlRelay;
import org.cougaar.core.security.services.crypto.CrlManagementService;
import org.cougaar.core.service.UIDServer;
import org.cougaar.core.util.UID;
import org.cougaar.planning.ldm.LDMServesPlugin;


final public class CrlManagement implements CrlManagementService {
  
  protected MessageAddress selfClusterId;
  protected UIDServer myUIDServer;
  private ServiceBroker serviceBroker;

 
  public CrlManagement() { }
  
  public CrlManagement(LDMServesPlugin ldm) {
    
    selfClusterId = ldm.getMessageAddress();
    myUIDServer = ldm.getUIDServer();
  }
  
  /**
   * @return a new <code>UID</code>
   */
  private  UID getNextUID() {
    return myUIDServer.nextUID();
  }
  
  public CrlRelay newCrlRelay(Object event, MessageAddress dest) {
    CrlRelay relay = new CrlRelay(getNextUID(), selfClusterId, dest, event,null);
    return relay;
  }
 
}
