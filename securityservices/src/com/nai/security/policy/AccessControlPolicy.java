/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
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

package com.nai.security.policy;

import org.cougaar.domain.planning.ldm.policy.*;
import com.nai.security.policy.*;

/**
 * Access control policy class instance and policy contstants. The constants
 * are specific to access control policy. An instance should have a specific 
 * target agent (or possibly a node).
 */
public class AccessControlPolicy extends TypedPolicy {

    /**
     * Name of rule parameter containing the agent's name.
     */
    private static final String AGENT_NAME_RULE = "agentName";

    // XML policy file constants used as keys for looking up policy

    // incoming message policy sections

    /**
     * Incoming message integrity level (Integer value)
     */
    public static String IN_MSG_INTEGRITY = "IncomingMessageIntegrity";
    /**
     * Incoming message criticality (Integer value)
     */
    public static String IN_MSG_CRITICALITY = "IncomingMessageCriticality";
    /**
     * Incoming message action { SET_ASIDE, FORWARD, ACCEPT }
     */
    public static String IN_MSG_ACTION = "IncomingMessageAction";

    /**
     * Incoming agent action { SET_ASIDE, FORWARD, ACCEPT }
     */
    public static String IN_AGENT_ACTION = "IncomingAgentAction";

    // outgoing message action policy sections

    /**
     * Outgoing message integrity level (Integer value)
     */
    public static String OUT_MSG_INTEGRITY = "OutgoingMessageIntegrity";
    /**
     * Outgoing message mission criticality (Integer value)
     */
    public static String OUT_MSG_CRITICALITY = "OutgoingMessageCriticality";
    /**
     * Outgoing message action { SET_ASIDE, FORWARD, ACCEPT }
     */
    public static String OUT_MSG_ACTION = "OutgoingMessageAction";
    /**
     * Outgoing message action { SET_ASIDE, FORWARD, ACCEPT }
     */
    public static String OUT_AGENT_ACTION = "OutgoingAgentAction";
    

    // Message action constants

    /**
     * A message action constant to redirect a message to another agent or
     * node. This can be used for incoming or outgoing messages.
     */
    public static String FORWARD = "ForwardTo";
    /**
     * A message action constant to allow a message to be accepted. Incoming
     * messages will be received by the agent and outgoing messages will be 
     * sent to the message transport service.
     */
    public static String ACCEPT = "AcceptMessage";
    /**
     * A message action constant to allow a message to be accepted. Incoming
     * messages will be received by the agent and outgoing messages will be 
     * sent to the message transport service.
     */

    public static String SET_ASIDE = "SetAside";

    /**
     * Constant used to determine a rule's default value.
     */
    public static final String DEFAULT = "DEFAULT";

  /**
   * default contructors which calls TypedPolicy constructor and name policy type
   */
  public AccessControlPolicy() {
    super("com.nai.security.policy.AccessControlPolicy");

  }

  /**
   * Returns the name for which this access control policy pertains.
   */
  public String getAgentName() 
  {
      RuleParameter nameRule = Lookup(AGENT_NAME_RULE);
      if(nameRule == null) {
	  String name = (String)nameRule.getValue();
	  if(name instanceof String) {
	      return name;
	  }
      }
      return "UNKNOWN";
  }

}









