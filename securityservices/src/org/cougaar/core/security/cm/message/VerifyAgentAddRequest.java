/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


package org.cougaar.core.security.cm.message;


import java.io.Serializable;

import org.cougaar.core.security.cm.CMMessage.CMRequest;


/**
 * A Configuration Manager Request for verifying and
 * 	add agent request.
 *
 * @author ttschampel
 * @version $Revision: 1.2 $
 */
public class VerifyAgentAddRequest implements CMRequest, Serializable {
  private String addToNode;
  private String agent;

  /**
   * Creates a new VerifyAgentAddRequest object.
   *
   * @param node name of the node that the agent is to be added to.
   * @param agentArg name of the agent being added to the node
   */
  public VerifyAgentAddRequest(String node, String agentArg) {
    this.addToNode = node;
    this.agent = agentArg;
  }

  /**
   * Get the name of the node that the agent is to be added to.
   *
   * @return node name
   */
  public String getAddToNode() {
    return addToNode;
  }


  /**
   * Get the name of the agent being added to the node
   * 
   * @return agent name
   */
  public String getAgent() {
    return agent;
  }
}
