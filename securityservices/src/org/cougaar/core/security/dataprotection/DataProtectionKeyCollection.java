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

package org.cougaar.core.security.dataprotection;

import org.cougaar.core.service.DataProtectionKey;

import java.util.ArrayList;

/**
 * A collection of keys used to encrypt the persisted blackboard.
 * The blackboard is encrypted using a SecretKey, which is itself
 * encrypted using public key technology. The SecretKey is always encrypted
 * with the agent key, and it may also be encrypted using the key
 * of one or more persistence management agents.
 * The first element of the list is always the SecretKey encrypted with
 * the agent's key.
 *
 * The List actually contains instances of the DataProtectionKeyImpl class.
 */
public class DataProtectionKeyCollection
  extends ArrayList
  implements DataProtectionKey
{
  private byte[] _sig;
  private long _timestamp;

  public void add(int index, Object element) {
    if (!(element instanceof DataProtectionKeyImpl)) {
      throw new IllegalArgumentException("Wrong data type: "
					 + element.getClass().getName());
    }
    super.add(index, element);
  }

  public boolean add(Object o) {
    if (!(o instanceof DataProtectionKeyImpl)) {
      throw new IllegalArgumentException("Wrong data type: "
					 + o.getClass().getName());
    }
    return super.add(o);
  }

  public Object set(int index, Object element) {
    if (!(element instanceof DataProtectionKeyImpl)) {
      throw new IllegalArgumentException("Wrong data type: "
					 + element.getClass().getName());
    }
    return super.set(index, element);
  }

  public byte[] getSignature() {
    return _sig;
  }

  public void setSignature(byte [] sig) {
    _sig = sig;
  }

  public void setTimestamp(long timestamp) {
    _timestamp = timestamp;
  }

  public long getTimestamp() {
    return _timestamp;
  }
}
