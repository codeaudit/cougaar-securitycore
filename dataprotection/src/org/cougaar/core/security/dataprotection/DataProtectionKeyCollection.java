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
