/**
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 *
 * Created on September 27, 2001, 3:35 PM
 */

package org.cougaar.core.security.services.acl;

// Cougaar core services
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.core.component.Service;

// Cougaar security services
import org.cougaar.core.security.acl.trust.*;

public interface AccessControlPolicyService 
  extends Service
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
    Object[] getIncomingVerbs(String target, String source);

    /**
     * Access control for directive verbs to target for inspection
     * on outgoing messages for a specified agent (or node in the future).
     * @param source The message's originator
     * @param target The message's intended recipient
     */
    Object[] getOutgoingVerbs(String source, String target);

}

