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

package org.cougaar.core.security.util;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.relay.Relay;
import org.cougaar.core.util.UID;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import java.lang.reflect.Constructor;
import java.util.Collections;
import java.util.Set;

public class RelayBase
  implements Relay.Source, Relay.Target, java.io.Serializable {

  private static Logger _log;

  protected UID _uid;
  protected MessageAddress _source;
  protected Object _content;
  protected Object _response;
  protected Set    _targets;
  private final Relay.TargetFactory FACTORY = 
    new RelayBaseFactory(this.getClass());

  static {
    _log = LoggerFactory.getInstance().createLogger(RelayBase.class);
  }

  protected RelayBase(UID uid, MessageAddress source, Object content) {
    _uid = uid;
    _source = source;
    _content = content;
    _response = null;
    _targets = null;
  }

  public RelayBase(UID uid, MessageAddress source, MessageAddress target) {
    this(uid, source, ((target == null)
                       ? Collections.EMPTY_SET 
                       : Collections.singleton(target)));
  }

  public RelayBase(UID uid, MessageAddress source, Set targets) {
    _uid = uid;
    _source = source;
    _content = null;
    _response = null;
    _targets = targets;
  }

  public UID getUID() { return _uid; }

  public void setUID(UID uid) { _uid = uid; }

  public Set getTargets() {
    return _targets;
  }

  public MessageAddress[] getTargetList() {
    if (_targets == null) {
      return new MessageAddress[0];
    }
    return (MessageAddress[]) 
      _targets.toArray(new MessageAddress[_targets.size()]);
  }

  public Object getContent() {
    return _content;
  }

  public void setContent(Object content) {
    _content = content;;
  }

  public Relay.TargetFactory getTargetFactory() {
    return FACTORY;
  }

  public int updateResponse(MessageAddress target, Object response) {
    if ((response == null && _response != null) ||
        (response != null && !response.equals(_response))) {
      _response = response;
      return Relay.RESPONSE_CHANGE;
    }
    return Relay.NO_CHANGE;
  }

  public MessageAddress getSource() {
    return _source;
  }

  public Object getResponse() {
    return _response;
  }

  public void setResponse(Object response) {
    _response = response;
  }

  public int updateContent(Object content, Token token) {
    if ((content == null && _content != null) ||
        (content != null && !content.equals(_content))) {
      _content = content;
      return Relay.CONTENT_CHANGE;
    }
    return Relay.NO_CHANGE;
  }

  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (!(o instanceof RelayBase)) {
      return false;
    }
    return _uid.equals(((RelayBase)o).getUID());
  }

  public int hashCode() {
    return _uid.hashCode();
  }

  public String toString() {
    return "RelayBase(" + _uid + ", " + _content + ", " + _response + ")";
  }

  public boolean isSource() {
    return (_targets != null);
  }

  public boolean isTarget() {
    return (_targets == null || _targets.contains(_source));
  }

  private static class RelayBaseFactory 
    implements Relay.TargetFactory, java.io.Serializable {
    private Class _relayClass;

    public RelayBaseFactory(Class relayClass) {
      _relayClass = relayClass;
    }

    public Relay.Target create(UID uid, MessageAddress source, 
                               Object content, Relay.Token token) {
      try {
        Class args[] = { UID.class, MessageAddress.class, Object.class };
        Constructor c = _relayClass.getConstructor(args);
        return (Relay.Target) 
          c.newInstance(new Object[] { uid, source, content});
      } catch (Exception e) {
        // shouldn't get here unless the coder has inherited
        // incorrectly from the RelayBase class
	if (_log.isWarnEnabled()) {
	  _log.warn("Shouldn't get here unless the coder has inherited "
		    + "incorrectly from the RelayBase class", e);
	}
        throw new RuntimeException(e.getMessage(), e);
      }
    }
  };

}
