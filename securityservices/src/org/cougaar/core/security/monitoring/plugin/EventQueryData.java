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
package org.cougaar.core.security.monitoring.plugin;

import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;

import java.io.Serializable;
import java.util.HashSet;

/**
 * This class is used by EventQueryPlugin to store data onto the
 * blackboard for persistence.
 */
public class EventQueryData implements Serializable, UniqueObject {
  public HashSet agents;
  public HashSet queryAdapters;
  public String  unaryPredicateClass;
  public String  classifications[];
  private UID _uid;

  public EventQueryData() {
  }

  public UID getUID() {
    return _uid;
  }

  public void setUID(UID uid) {
    _uid = uid;
  }

  /** Used only for XMLizable */
  public String getUnaryPredicateClass() {
    return unaryPredicateClass;
  }

  /** Used only for XMLizable */
  public String[] getCapabilities() {
    return classifications;
  }

  /** Used only for XMLizable */
  public int getAdapterCount() {
    return queryAdapters.size();
  }

  /** Used only for XMLizable */
  public HashSet getAgents() {
    return agents;
  }
}

