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

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.util.List;
import java.util.ArrayList;

public class CertificateValidityMonitor
  implements CertValidityService, Runnable {
  KeyRingService keyRing = null;
  SecurityPropertiesService secprop = null;
  LoggingService log = null;

  static Hashtable certListeners = new Hashtable();
  static List validityListeners = new ArrayList();
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
    Thread td=new Thread(this,"validitythread");
    td.setPriority(Thread.NORM_PRIORITY);
    td.start();
  }

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

      if(log.isDebugEnabled()) {
	log.debug("**************** CertificateValidity THREAD IS RUNNING ***********************************");
      }

      if (keyRing == null) {
	log.warn("Unable to update certificate. KeyRing service is null");
	continue;
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
          keyRing.checkExpiry(commonName);
        }
      }
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
  }

  public void updateCertificate(String commonName) {
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
}
