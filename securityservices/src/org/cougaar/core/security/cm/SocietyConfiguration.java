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


package org.cougaar.core.security.cm;


import java.io.Serializable;
import java.util.HashMap;

import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;


/**
 * Society Configuration Value Object
 *
 * @author ttschampel
 * @version $Revision: 1.1 $
 */
public class SocietyConfiguration implements Serializable, UniqueObject {
  private HashMap agentConfigurations;
  private UID uid;

	/**
	 * @return
	 */
	public HashMap getAgentConfigurations() {
		return agentConfigurations;
	}

  /**
   * Creates a new SocietyConfiguration object.
   *
   * @param list List of agent to node mappings.
   */
  public SocietyConfiguration(HashMap list) {
    this.agentConfigurations = list;
  }

  /**
   *Gets UID
   */
  public UID getUID() {
    return uid;
  }


  /**
   *Sets UID
   */
  public void setUID(UID arg0) {
    uid = arg0;
  }
}
