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
import java.util.Date;

/**
 * This class is used by RateCalculatorPlugin to store data that
 * it needs to persist.
 */
public class RateCalculatorInfo 
  implements Serializable, UniqueObject {

  public RateCalculatorInfo(int [] messages, long startTime,
                            long lastUpdate, String conditionName,
                            UID uid) {
    this.messages = messages;
    this.startTime = startTime;
    this.lastUpdate = lastUpdate;
    this.conditionName = conditionName;
    _uid = uid;
  }

  public UID getUID() {
    return _uid;
  }

  public void setUID(UID uid) {
    _uid = uid;
  }

  /** Used only for XMLizable */
  public String getStartTime() {
    return (new Date(startTime)).toString();
  }

  /** Used only for XMLizable */
  public String getLastUpdate() {
    return (new Date(lastUpdate)).toString();
  }

  /** Used only for XMLizable */
  public String getConditionName() {
    return conditionName;
  }

  public String toString() {
    return "(" + _uid + ", " + startTime + ", " + lastUpdate + ")";
  }

  /** Used only for XMLizable */
  public int getTotalMessages() {
    int count = 0;
    for (int i = 0; i < messages.length; i++) {
      count += messages[i];
    } // end of for (int i = 0; i < messages.length; i++)
    return count;
  }

  int  messages[];
  long startTime;
  long lastUpdate;
  String conditionName;
  UID _uid;
}

