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

package org.cougaar.core.security.dataprotection;

import java.util.*;

public class DataProtectionStatus {
  public static final String INPUT_COMPLETE = "INPUT_COMPLETE";
  public static final String OUTPUT_COMPLETE = "OUTPUT_COMPLETE";
  public static final String RECOVERY_REQUEST = "RECOVERY_REQUEST";
  public static final String KEY_RECOVERED = "KEY_RECOVERED";

  public long timestamp;
  public String agent;
  public String status;

  private static Hashtable inputStatus;
  private static Hashtable outputStatus;

  public DataProtectionStatus(long timestamp, String agent, String status) {
    this.timestamp = timestamp;
    this.agent = agent;
    this.status = status;
  }

  public static void addInputStatus(String agent, String status) {
    addStatus(inputStatus, agent, status);
  }

  public static void addOutputStatus(String agent, String status) {
    addStatus(outputStatus, agent, status);
  }

  public static Hashtable getInputStatus() {
    return inputStatus;
  }

  public static void initStatus() {
    inputStatus = new Hashtable();
    outputStatus = new Hashtable();
  }

  public static Hashtable getOutputStatus() {
    return outputStatus;
  }

  private static void addStatus(Hashtable t, String agent, String status) {
    // add status only after servlet init status
    // prevents test case to affect the normal operations and consume memory
    // if this is not setup to run test cases
    if (t == null) {
      return;
    }

    List l = (List)t.get(agent);
    if (l == null) {
      l = new ArrayList();
      t.put(agent, l);
    }
    long time = System.currentTimeMillis();
    l.add(new DataProtectionStatus(time, agent, status));

    // only keep half 30 minutes log by default
    DataProtectionStatus s = (DataProtectionStatus)l.get(0);
    long elapse = s.timestamp - time;
    if (elapse > 30 * 60 * 1000) {
      l.remove(0);
    }
  }
}