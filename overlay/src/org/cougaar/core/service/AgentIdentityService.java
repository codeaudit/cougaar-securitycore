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

package org.cougaar.core.service;

import java.security.Principal;

// Cougaar core services
import org.cougaar.core.component.Service;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.coreservices.identity.*;

public interface AgentIdentityService
  extends Service
{
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
   *  Issue 1: There is a very weak notion of agent identity.
   *  Cougaar currently uses a String to represent the name
   *  of an agent but this should be changed.
   *
   *  Issue 2: This service could be called either by the node
   *  agent or the agent itself.
   *  In the first case, the node agent calls the API for
   *  all agents including the node agent itself. The node
   *  agent receives a notification from the crypto service
   *  when an agent has been revoked. An advantage is that
   *  the node agent can take an action such as shutting down
   *  the revoked agent.
   *  In the second case, the agent itself would have to be
   *  trusted to shut down itself when it has been revoked.
   *	The API is currently written for the first case.
   *  
   *  It is assumed that the user of the service will respond
   *  appropriately when an agent has been revoked.
   *
   * @param      agentName the name of the agent
   * @param      clientCallBack a callBack to the client
   * @exception  PendingRequestException the certificate authority
   *             did not sign the request immediately. The same request
   *             should be sent again later
   * @exception  IdentityDeniedException the certificiate authority
   *             refused to sign the key
   */
  public void CreateCryptographicIdentity(MessageAddress agent,
					  RevocationCallBack clientCallBack)
    throws PendingRequestException,
    IdentityDeniedException;

  /** 
   */
  public void CreateCryptographicIdentity(Principal p,
					  RevocationCallBack clientCallBack)
    throws PendingRequestException,
    IdentityDeniedException;

  /**
   */
  public void HoldCryptographicIdentity(MessageAddress agent);

  /**
   */
  public void RevokeCryptographicIdentity(MessageAddress agent);

  /**
   *  Notify the cryptographic service that an agent is about
   *  to move to another node.
   *  Depending on the cryptographic policy:
   *  - Wrap agent key pair and protect it with remote node public key
   *  - Revoke agent key (remote node must create a new key)
   *
   * Issues/comments:
   * - Is there a way to identify entities without using strings?
   * - The agent mobility service has some specific requirements
   *   (see security framework document), therefore the identity service
   *   cannot be used to move an agent.
   *
   * @param agentName        the name of the agent to be moved
   * @param targetNodeAgent  the name of the remote node agent
   * @return an encrypted object that should be sent to the remote
   * node agent
   */
  public TransferableIdentity initiateTransfer(MessageAddress agent,
					       MessageAddress sourceAgent,
					       MessageAddress targetAgent);

  /** Notify the cryptographic service that an agent previously
   *  running on a remote node is about to be installed and
   *  executed on the local node.
   *  
   * @param cryptoAgentData  the data that was returned by a
   * call to moveAgent on the remote node, and then sent to
   * the local node through a Cougaar message
   * @param agentName        the name of the agent to be installed
   */
  public void completeTransfer(TransferableIdentity identity,
			       MessageAddress sourceAgent,
			       MessageAddress targetAgent);

}

