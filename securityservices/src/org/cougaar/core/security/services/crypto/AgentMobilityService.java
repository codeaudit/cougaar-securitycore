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

package org.cougaar.core.security.services.crypto;

import org.cougaar.core.component.Service;

public interface AgentMobilityService extends Service {

  /** Notify the cryptographic service that an agent is about
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
  public Object moveAgentTo(String agentName, String targetNodeAgent);

  /** Notify the cryptographic service that an agent previously
   *  running on a remote node is about to be installed and
   *  executed on the local node.
   *  
   * @param cryptoAgentData  the data that was returned by a
   * call to moveAgent on the remote node, and then sent to
   * the local node through a Cougaar message
   * @param agentName        the name of the agent to be installed
   */
  public void moveAgentFrom(String agentName, Object cryptoAgentData);

}
