/*
 * <copyright>
 *  Copyright 1997-2002 Networks Associates Technology, Inc.
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

package org.cougaar.core.service.identity;

import java.security.Principal;

// Cougaar core services
import org.cougaar.core.component.Service;
import org.cougaar.core.mts.MessageAddress;

/**
 * AgentIdentityService
 * This service should be called by every agent, including
 * the NodeAgent.
 *
 * The requestor must implement AgentIdentityClient.
 */
public interface AgentIdentityService
  extends Service
{
  /** Creates a cryptographic identity for an agent. 
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
   *  If the 'id' parameter is not null, the cryptographic service
   *  attempts to install keys from an agent that was previously
   *  running on a remote node. The 'id' parameter should be the
   *  TransferableIdentity object that was returned on the original
   *  host when transferTo() was called.
   *  The TransferableIdentity should then have been sent to the
   *  new host when the agent was moved.
   *  
   * @param id the identity of an agent that was moved from another node.
   *
   * @exception  PendingRequestException the certificate authority
   *             did not sign the request immediately. The same request
   *             should be sent again later
   * @exception  IdentityDeniedException the certificiate authority
   *             refused to sign the key
   */
  void acquire(TransferableIdentity id)
    throws PendingRequestException,
    IdentityDeniedException;

  /** Notifies the cryptographic service that the cryptographic identity
   *  of the requestor is no longer needed.
   *  This does not mean the key should be revoked or deleted.
   *  The key is not used until the agent is restarted.
   */
  void release();

  /**
   *  Notify the cryptographic service that an agent is about
   *  to move to another node.
   *  Depending on the cryptographic policy:
   *  - Wrap agent key pair and protect it with remote node public key
   *  - Revoke agent key (remote node must create a new key)
   *
   * @param targetNode       the name of the remote NodeAgentagent where
   *                         the agent will be run next.
   * @return an encrypted object that should be sent to the remote
   * node agent
   */
  TransferableIdentity transferTo(MessageAddress targetNode);

}

