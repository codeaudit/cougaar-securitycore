/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.policy.mediator;

import org.cougaar.core.security.acl.trust.TrustSet;



public interface XmlPolicyMediator extends PolicyMediator
{
 
  TrustSet getIncomingTrust(String agent, String key);
  TrustSet getOutgoingTrust(String agent, String key);
  String getIncomingAction(String agent, String level);
  String getOutgoingAction(String agent, String level);
 
  /**
   * Access control policy based on source agent.
   * @param target The agent the message is being delivered to
   * @param source The agent where the message originated
   */
  String getIncomingAgentAction(String target, String source);

  /**
   * Access control policy based on destination agent
   * @param source The agent attempting to send a message
   * @param target The inteded recipient of the message to be sent
   */
  String getOutgoingAgentAction(String source, String target);

  /**
   * Access control for directive verbs to target for inspection
   * on incoming messages for a specified agent (or node in the future).
   * @param target The message's intended recipient
   * @param source The message's originator
   */
  String[] getIncomingVerbs(String target, String source);

  /**
   * Access control for directive verbs to target for inspection
   * on outgoing messages for a specified agent (or node in the future).
   * @param source The message's originator
   * @param target The message's intended recipient
   */
  String[] getOutgoingVerbs(String source, String target);

}

