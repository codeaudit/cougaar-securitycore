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


package org.cougaar.core.security.blackboard;


import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;

import java.io.Serializable;


/**
 * Object marking the compromise of the Blackboard
 *
 * @author ttschampel
 */
public class CompromiseBlackboard implements UniqueObject, Serializable {
  private UID uid;
  private long timestamp;

  /**
   * Get UID
   *
   * @return UID
   */
  public UID getUID() {
    return uid;
  }


  /**
   * set the UID
   *
   * @param arg0 UID
   */
  public void setUID(UID arg0) {
    uid = arg0;

  }


  /**
   * get Timestamp of the compromise
   *
   * @return Timestamp of the compromise
   */
  public long getTimestamp() {
    return timestamp;

  }


  /**
   * set Timestamp of the compromise
   *
   * @param l Timestamp of the compromise
   */
  public void setTimestamp(long l) {
    timestamp = l;
  }
}
