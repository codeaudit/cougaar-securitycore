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
package org.cougaar.core.security.ssl;

import java.util.List;
import java.util.Iterator;
import java.util.Enumeration;
import java.util.ArrayList;
import java.util.Hashtable;
import java.net.Socket;
import java.net.ServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

// Cougaar core services
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

/**
 * SSLSocketCache keeps a cache of all SSL sockets.
 * This allows the cryptographic service to forcibly close SSL sockets
 * if necessary. For instance, sockets could be closed if a certificate
 * used in the SSL handshake has been revoked.
 *
 * @author Sebastien Rosset <srosset@nai.com>
 */
public class SSLSocketCache
  extends Hashtable
{
  public static final String SSLSESSION_CLOSING_SOCKETS = "Closing SSL sockets";
  public static final String SSLSESSION_INVALIDATE = "Invalidating SSL session";

  private static Logger            _log;

  public SSLSocketCache() {
    _log = LoggerFactory.getInstance().createLogger(getClass());
  }
  
  /** Add an SSLSession to the hashtable.
   *  The key should be an instance of SSLSession
   *  and the value should be an instance of Socket. */
  public Object put(Object key, Object value) {
    if (!(key instanceof SSLSession)) {
      throw new IllegalArgumentException("Wrong key type:" +
					 key.getClass().getName());
    }
    if (!(value instanceof Socket)) {
      throw new IllegalArgumentException("Wrong value type:" +
					 value.getClass().getName());
    }
    Object o = get(key);
    if (o == null) {
      ArrayList array = new ArrayList();
      array.add(value);
      return super.put(key, array);
    }
    else {
      return super.put(key, value);
    }
  }

  private interface EventActor {
    public void execute(SSLSession session);
  }

  private class EventInvalidator 
    implements EventActor {
    public void execute(SSLSession session) {
      if (_log.isInfoEnabled()) {
	_log.info("Invalidating SSL session");
      }

      // notify potential observers
      SSLSessionBindingEvent event =
	new SSLSessionBindingEvent(session, SSLSESSION_INVALIDATE);

      // Invalidate future sessions
      session.invalidate();
    }
  }

  private class EventSocketKiller 
    extends EventInvalidator {

    public void execute(SSLSession session) {
      super.execute(session);

      // Close existing sockets
      if (_log.isInfoEnabled()) {
	_log.info("Closing SSL sockets");
      }

      // notify potential observers
      SSLSessionBindingEvent event =
	new SSLSessionBindingEvent(session, SSLSESSION_CLOSING_SOCKETS);

      List socketList = (List) get(session);
      Iterator it = socketList.iterator();
      while (it.hasNext()) {
	Object o = it.next();
	if (o instanceof Socket) {
	  Socket s = (Socket) o;
	  if (s.isClosed()) {
	    continue;
	  }
	  if (s instanceof SSLSocket) {
	    try {
	      s.close();
	    }
	    catch (java.io.IOException e) {
	      _log.warn("Unable to close SSL socket: " + e);
	    }
	  }
	  else {
	    if (_log.isWarnEnabled()) {
	      _log.warn("Unexpected socket type:" + s.getClass().getName());
	    }
	  }
	}
	else {
	  if (_log.isWarnEnabled()) {
	    _log.warn("Unexpected object type:" + o.getClass().getName());
	  }
	}
      }
    }
  }

  /** Invalidate future sessions that would use a given certificate. */
  public void invalidate(X509Certificate cert) {
    onCertificateEvent(cert, new EventInvalidator());
  }

  /** Close SSL sockets for which the SSLSession use a given certificate. */
  public void closeSockets(X509Certificate cert) {
    onCertificateEvent(cert, new EventSocketKiller());
  }

  /** Take an action for all SSL sessions for which the SSLsession use
      a given certificate. */
  public void onCertificateEvent(X509Certificate cert, EventActor actor) {
    Enumeration enum = keys();
    while (enum.hasMoreElements()) {
      SSLSession session = (SSLSession) enum.nextElement();
      if (containsCert(session, cert)) {
	actor.execute(session);
      }
    }
  }

  private boolean containsCert(SSLSession session, X509Certificate cert) {
    Certificate[] localCertChain = session.getLocalCertificates();
    if (localCertChain == null) {
      return false;
    }
    for (int i = 0 ; i < localCertChain.length ; i++) {
      if (localCertChain[i].equals(cert)) {
	return true;
      }
    }
    try {
      Certificate[] peerCertChain = session.getPeerCertificates();
      for (int i = 0 ; i < peerCertChain.length ; i++) {
	if (peerCertChain[i].equals(cert)) {
	  return true;
	}
      }
    }
    catch (javax.net.ssl.SSLPeerUnverifiedException e) {
      _log.warn("Unable to get peer certificate chain: " + e);
    }
    return false;
  }
}
