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

package org.cougaar.core.security.services.identity;

import org.cougaar.core.component.Service;

public interface AgentIdentityService extends Service {
  /** Create a cryptographic identity for an agent. 
   *  This method is called by Cougaar core services before
   *  an agent is initialized.
   *
   *  If the agent already has a cryptographic identity, the
   *  method returns immediately. If the agent does not have
   *  a cryptographic key, or if no key is valid, a new key
   *  is created.
   *
   *  This service provider will call checkPermission() to
   *  make sure that only known entities will call the service.
   *
   *  Issue: There is a very weak notion of agent identity.
   *  Cougaar currently uses a String to represent the name
   *  of an agent but this should be changed.
   *
   * @param      agentName the name of the agent
   * @param      clientCallBack a callBack to the client
   * @exception  PendingRequestException the certificate authority
   *             did not sign the request immediately. The same request
   *             should be sent again later
   * @exception  IdentityDeniedException the certificiate authority
   *             refused to sign the key
   */
  public void CreateCryptographicIdentity(String agentName,
					  RevocationCallBack clientCallBack)
    throws PendingRequestException,
	   IdentityDeniedException;

  /**
   */
  public void HoldCryptographicIdentity(String agentName);

  /**
   */
  public void RevokeCryptographicIdentity(String agentName);
}

