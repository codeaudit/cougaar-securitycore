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

import java.util.Set;
import java.util.Collections;
import java.security.cert.X509Certificate;

// Cougaar core services
import org.cougaar.core.relay.Relay;
import org.cougaar.planning.servlet.XMLize;
import org.cougaar.core.util.UID;
import org.cougaar.core.mts.MessageAddress;

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
public class DataProtectionKeyUnlockRequest
  implements Relay.Source, Relay.Target
{
  private MessageAddress source;
  private MessageAddress target;
  private UID uid;
  private transient Set _targets;

  /** The request content sent by the data protection service to the
   *  Persistence Management Agent.
   *  The content should always be an instance of the DataProtectionRequestContent class.
   */
  private Object content;

  /** The response is the SecretKey which should be re-encrypted with the new agent's key.
   *  This method should be called by the persistence manager agent when it
   *  receives a request by a remote data protection service. This occurs when
   *  the remote service was unable to decrypt the data and asks the persistence
   *  manager to decrypt the key and re-encrypt it with the new agent's key.
   * The response should always be an instance of the DataProtectionKeyImpl class.
   */
  private Object response;
  
  public DataProtectionKeyUnlockRequest(UID uid, MessageAddress source, MessageAddress target,
					DataProtectionKeyCollection kc,
					X509Certificate[] certChain) {
    this(uid, source, target,
	 new DataProtectionRequestContent(kc, certChain), null);
  }

  public DataProtectionKeyUnlockRequest(UID uid, MessageAddress source, MessageAddress target,
					Object req, Object response) {
    if (!(req instanceof DataProtectionRequestContent)) {
      throw new IllegalArgumentException("content is not of the expected type");
    }
    this.uid = uid;
    this.source = source;
    this.target = target;
    this.content = req;
    this.response = response;

    this._targets = 
     ((target != null) ?
      Collections.singleton(target) :
      Collections.EMPTY_SET);

  }

  // UniqueObject interface
  public void setUID(UID uid) {
    throw new RuntimeException("Attempt to change UID");
  }
  public UID getUID() {
    return uid;
  }


  // Source interface
  public Set getTargets() {
    return _targets;
  }
  public Object getContent() {
    return content;
  }

  private static final class SimpleRelayFactory
    implements TargetFactory, java.io.Serializable {

    public static final SimpleRelayFactory INSTANCE = 
      new SimpleRelayFactory();

    private SimpleRelayFactory() {}

    public Relay.Target create(
        UID uid, 
        MessageAddress source, 
        Object content,
        Token token) {
      return new DataProtectionKeyUnlockRequest(
	uid, source, null, content, null);
    }

    private Object readResolve() {
      return INSTANCE;
    }
  };

  public TargetFactory getTargetFactory() {
    return SimpleRelayFactory.INSTANCE;
  }

  public int updateResponse(MessageAddress t, Object response) {
    // assert response != null
    if (!(response.equals(this.response))) {
      this.response = response;
      return Relay.RESPONSE_CHANGE;
    }
    return Relay.NO_CHANGE;
  }

  // Target interface
  public MessageAddress getSource() {
    return source;
  }
  public Object getResponse() {
    return response;
  }
  public int updateContent(Object content, Token token) {
    // assert content != null
    if (!(content.equals(this.content))) {
      this.content = content;
      return CONTENT_CHANGE;
    }
    return NO_CHANGE;
  }

  public boolean equals(Object o) {
    if (o == this) {
      return true;
    } else if (!(o instanceof DataProtectionKeyUnlockRequest)) {
      return false;
    } else {
      UID u = ((DataProtectionKeyUnlockRequest) o).getUID();
      return uid.equals(u);
    }
  }

  public int hashCode() {
    return uid.hashCode();
  }

  public String toString() {
    return "("+uid+", "+content+", "+response+")";
  }

  /** Get the target address.
   * Not part of any interface, but allows the object to be displayed with the target
   * in the /task servlet.
   */
  public MessageAddress getTarget() {
    return target;
  }
}
