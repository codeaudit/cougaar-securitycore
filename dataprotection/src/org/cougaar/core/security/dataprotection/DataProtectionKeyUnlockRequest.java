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

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.relay.Relay;
import org.cougaar.core.util.UID;

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
