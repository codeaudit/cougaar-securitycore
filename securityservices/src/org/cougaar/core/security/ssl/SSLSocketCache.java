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

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.Enumeration;
import java.util.WeakHashMap;
import java.util.Map;
import java.util.Iterator;
import java.util.List;
import java.lang.ref.WeakReference;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSocket;

/**
 * SSLSocketCache keeps a cache of all SSL sockets.
 * This allows the cryptographic service to forcibly close SSL sockets
 * if necessary. For instance, sockets could be closed if a certificate
 * used in the SSL handshake has been revoked.
 *
 * @author Sebastien Rosset <srosset@nai.com>
 */
public class SSLSocketCache
{
  public static final String SSLSESSION_CLOSING_SOCKETS = "Closing SSL sockets";
  public static final String SSLSESSION_INVALIDATE = "Invalidating SSL session";
  public static final String SSLSESSION_CLEAR_INTERVAL = 
  "org.cougaar.core.security.ssl.session_clear_interval";
  public static final int    SSLSESSION_DEFAULT_INTERVAL = 10 * 1000;

  private static Logger            _log;
  private        WeakHashMap       _map = new WeakHashMap();

  public SSLSocketCache() {
    _log = LoggerFactory.getInstance().createLogger(getClass());
    String prop = System.getProperty(SSLSESSION_CLEAR_INTERVAL);
    int interval = SSLSESSION_DEFAULT_INTERVAL;
    if (prop != null) {
      try {
	interval = Integer.parseInt(prop) * 1000;
      } catch (NumberFormatException e) {
	_log.warn("Property value for " + SSLSESSION_CLEAR_INTERVAL + 
		  " must be an integer value. Got (" + prop + "), " +
		  "using " + (SSLSESSION_DEFAULT_INTERVAL/1000) +
		  " second default value.");
      }
    }
    Thread t = new ClearSocketsThread(_map, _log, interval);
    t.start();
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

    synchronized (_map) {
      Object o = _map.get(key);
      if (o == null) {
        LinkedList list = new LinkedList();
        list.add(new WeakReference(value));
        return _map.put(key, list);
      }
      else {
        // o must be list
// 	clearWeakList((List) o);
        ((List)o).add(new WeakReference(value));
        return _map.put(key, o);
      }
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

      synchronized (_map) {
	List socketList = (List) _map.get(session);
	Iterator it = socketList.iterator();
	while (it.hasNext()) {
	  WeakReference r = (WeakReference) it.next();
	  Object o = r.get();
	  if (o == null) {
	    continue;
	  }
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
	    } else {
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
    synchronized (_map) {
      Iterator iter = _map.keySet().iterator();
      while (iter.hasNext()) {
	SSLSession session = (SSLSession) iter.next();
	if (containsCert(session, cert)) {
	  actor.execute(session);
	}
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

  private static class ClearSocketsThread extends Thread {
    WeakReference _mapRef;
    Logger        _log;
    int           _interval;
    public ClearSocketsThread(Map m, Logger log, int interval) {
      _mapRef = new WeakReference(m);
      _log = log;
      _interval = interval;
    }

    public void run() {
      Map m;
      while ((m = (Map)_mapRef.get()) != null) {
	int count = clearClosedSockets(m);
	if (_log.isDebugEnabled()) {
	  _log.debug("Removed " + count + " sockets from SSLScoketCache, " +
		     "total entries now: " + getTotalEntries(m));
	}
	m = null;
	try {
	  sleep(_interval);
	} catch (Exception e) {
	  // I don't care
	}
      }
    }

    private static int clearSocketList(List l) {
      Iterator iter = l.iterator();
      int count = 0;
      while (iter.hasNext()) {
	WeakReference r = (WeakReference) iter.next();
	Socket s = (Socket) r.get();
	if (s == null || s.isClosed()) {
	  iter.remove();
	  count++;
	}
      }
      return count;
    }

    private static int clearClosedSockets(Map map) {
      int count = 0;
      synchronized (map) {
	Iterator iter = map.entrySet().iterator();
	while (iter.hasNext()) {
	  Map.Entry entry = (Map.Entry) iter.next();
	  List l = (List) entry.getValue();
	  count += clearSocketList(l);
	  if (l.isEmpty()) {
	    iter.remove();
	  }
	}
      }
      return count;
    }

    private static int getTotalEntries(Map map) {
      int count = 0;
      synchronized (map) {
	Iterator iter = map.values().iterator();
	while (iter.hasNext()) {
	  List l = (List) iter.next();
	  count += l.size();
	}
      }
      return count;
    }

  }
}
