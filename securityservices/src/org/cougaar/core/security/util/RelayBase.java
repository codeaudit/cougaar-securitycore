/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
  protected transient Set _targets;
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
