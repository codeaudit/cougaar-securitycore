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

package org.cougaar.core.security.crypto;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.crypto.CertValidityService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.security.policy.TrustedCaPolicy;

import sun.security.x509.X500Name;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

public class CertificateValidityMonitor
  implements CertValidityService/*, Runnable*/ {
  KeyRingService keyRing = null;
  SecurityPropertiesService secprop = null;
  LoggingService log = null;

  static Hashtable certListeners = new Hashtable();
  static Hashtable _certRequests = new Hashtable();
  static List validityListeners = new ArrayList();
  static List availListeners = new ArrayList();
  static List invalidatedNames = new ArrayList();

  long sleep_time = 60L * 60L * 1000L; // checking every hour

  public CertificateValidityMonitor(ServiceBroker sb) {
    ServiceBroker serviceBroker = sb;

    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class, null);

    keyRing = (KeyRingService)
      serviceBroker.getService(this,
			       KeyRingService.class, null);

    long poll = 0;
    try {
      poll = (Long.valueOf(secprop.getProperty(secprop.VALIDITY_POLLING_PERIOD))).longValue() * 1000;
    }
    catch (Exception e) {}
    if (poll != 0) {
      sleep_time = poll;
    }
/*
    Thread td=new Thread(this,"validitythread");
    td.setPriority(Thread.NORM_PRIORITY);
    td.start();
*/
    ThreadService threadService = (ThreadService)
      serviceBroker.getService(this, ThreadService.class, null);
    if (threadService == null) {
      serviceBroker.addServiceListener(new ServiceAvailableListener() {
        public void serviceAvailable(ServiceAvailableEvent ae) {
          if (ae.getService() == ThreadService.class) {
            ThreadService threadsrv = (ThreadService)
              ae.getServiceBroker().getService(this, ThreadService.class, null);
            startThread(threadsrv);
          }
        }
      });
    }
    else {
      startThread(threadService);
    }
  }

  public void startThread(ThreadService threadService) {
    threadService.getThread(this, new ValidityMonitor()).
      schedule(0, sleep_time);

    // start another thread for certificate requests that fail
    // this thread should be much faster
    int waittime = 10000;
      try {
        String waitPoll = System.getProperty("org.cougaar.core.security.configpoll", "5000");
        waittime = Integer.parseInt(waitPoll);
      } catch (Exception ex) {
        if (log.isWarnEnabled()) {
          log.warn("Unable to parse configpoll property: " + ex.toString());
        }
      }
    threadService.getThread(this, new CertRequestMonitor()).
      schedule(0, waittime);
  }

/*
  public void run() {
    while(true) {
      try {
	Thread.sleep(sleep_time);
      }
      catch(InterruptedException interruptedexp) {
	if (log.isWarnEnabled()) {
	  log.warn("Thread interrupted", interruptedexp);
	}
      }
*/

  private class ValidityMonitor implements Runnable {
    public void run() {
      Thread.currentThread().setPriority(Thread.MIN_PRIORITY);

      if(log.isDebugEnabled()) {
	log.debug("**************** CertificateValidity THREAD IS RUNNING ***********************************");
      }

      if (keyRing == null) {
	log.warn("Unable to update certificate. KeyRing service is null");
	//continue;
        return;
      }

      Vector list = new Vector();
      keyRing.checkExpiry(NodeInfo.getNodeName());
      // node in priority
      // CA cert should not be in validity checking, otherwise CA cert should be
      // checked first
      for (Enumeration enum = certListeners.keys(); enum.hasMoreElements(); ) {
        String commonName = (String)enum.nextElement();
        if (!commonName.equals(NodeInfo.getNodeName())) {
          //checkValidity(commonName);

          if (isInvalidated(commonName)) {
            log.warn(commonName + " has been revoked, not generating request to renew certificate");
            return;
          }
          keyRing.checkExpiry(commonName);
        }
      }
    }
  }

/*
  private void checkExpiry(String commonName) {
    // if the first certificate is not generated yet, no need to checkExpiry
    List list = keyRing.findCert(commonName, KeyRingService.LOOKUP_KEYSTORE, false);
    if (list == null || list.size() == 0) {
      if (log.isDebugEnabled()) {
        log.debug("Certificate for " + commonName + " is not generated yet, not checking expiry.");
      }
      return;
    }

    keyRing.checkExpiry(commonName);
  }
*/

  private class CertRequestMonitor implements Runnable {
    public void run() {
      Thread.currentThread().setPriority(Thread.MIN_PRIORITY);

      if(log.isDebugEnabled()) {
        log.debug("CertRequestor Thread running ******************");
      }

      List requests = new ArrayList();
      requests.addAll(_certRequests.values());
    
        for (Iterator it = requests.iterator(); it.hasNext(); ) {
          CertRequestInfo info = (CertRequestInfo)it.next();
          if (log.isDebugEnabled()) {
            log.debug("processing " + info.m_dname);
          }
          keyRing.checkOrMakeCert(info.m_dname, info.m_isCA, info.m_trustPolicy);
          List list = keyRing.findCert(info.m_dname, KeyRing.LOOKUP_KEYSTORE, true);
          if (list != null && list.size() != 0) {
            if (log.isDebugEnabled()) {
              log.debug("Acquired " + info.m_dname);
            }

            keyRing.updateNS(info.m_dname);
            _certRequests.remove(info.m_dname.toString());
          }
          else {
            // if fail to get certificate, it is probably because CA is busy
            // do not make additional request because they will simply jam
            // CA more
            break;
          }
        }
    }
  }

  public void addCertRequest(X500Name dname, boolean isCA, TrustedCaPolicy trustPolicy) {
    if (log.isDebugEnabled()) {
      log.debug("addCertRequest: " + dname + " policy " + trustPolicy);
    }
    _certRequests.put(dname.toString(),
      new CertRequestInfo(dname, isCA, trustPolicy));
  }

  class CertRequestInfo {
    X500Name m_dname;
    boolean m_isCA;
    TrustedCaPolicy m_trustPolicy;

    CertRequestInfo(X500Name dname, boolean isCA, TrustedCaPolicy trustPolicy) {
      m_dname = dname;
      m_isCA = isCA;
      m_trustPolicy = trustPolicy;
    }  
  }

  /*
  private void checkValidity(String commonName) {
    boolean updated = false;
    // expriy check
    if (keyRing.checkExpiry(commonName)) {
      Vector v = (Vector)certListeners.get(commonName);
      for (int i = 0; i < v.size(); i++) {
        CertValidityListener listener = (CertValidityListener)v.get(i);
        listener.updateCertificate();
      }
    }
  }
  */

  public void invalidate(String commonName) {
    for (int i = 0; i < validityListeners.size(); i++) {
      CertValidityListener listener = (CertValidityListener)
        validityListeners.get(i);
      listener.invalidate(commonName);
    }

    certListeners.remove(commonName);
    invalidatedNames.add(commonName);
  }

  public boolean isInvalidated(String commonName) {
    return invalidatedNames.contains(commonName);
  }

  public void updateCertificate(String commonName) {
    for (int i = 0; i < availListeners.size(); i++) {
      CertValidityListener listener = (CertValidityListener)
        availListeners.get(i);
      listener.updateCertificate();
    }
    Vector v = (Vector)certListeners.get(commonName);
    if (v == null) {
      return;
    }
    for (int i = 0; i < v.size(); i++) {
      CertValidityListener listener = (CertValidityListener)v.get(i);
      listener.updateCertificate();
    }
  }

  public void addValidityListener(CertValidityListener listener) {
    String name = listener.getName();
    if (name == null) {
      log.warn("No name for listener, cannot apply to addValidityListener");
      return;
    }

    Vector v = (Vector)certListeners.get(name);
    if (v == null) {
      v = new Vector();
      certListeners.put(listener.getName(), v);
    }
    v.add(listener);
  }

  public void addInvalidateListener(CertValidityListener listener) {
    validityListeners.add(listener);
  }

  public void addAvailabilityListener(CertValidityListener listener) {
    availListeners.add(listener);
  }
}
