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

import java.io.*;
import java.util.*;
import java.security.Principal;
import sun.security.x509.*;
import java.security.cert.*;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.util.*;

public class NameMapping {
  private ServiceBroker serviceBroker;
  private LoggingService log;
  /** Key: a common name
   *  Value: an X500Principal
   */
  private Hashtable cn2dn;

  public NameMapping(ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    cn2dn = new Hashtable(50);
  }

  public void addName(CertificateStatus certStatus) {
    X509Certificate cert = certStatus.getCertificate();
    // Retrieve the distinguished name, which is used as a key in
    // the certificate cache.
    Principal principal = cert.getSubjectDN();
    addName(principal);
  }

  private void addName(Principal principal)
    throws IllegalArgumentException
  {
    if (log.isDebugEnabled()) {
      log.debug("Add name:" + principal.getName());
    }
    X500Name x500Name = null;
    String cn = null;
    if (principal == null) {
      throw new IllegalArgumentException("ERROR: cannot add null principal");
    }
    try {
      x500Name = new X500Name(principal.getName());
      cn = x500Name.getCommonName();
    } catch(Exception e) {
      if (log.isDebugEnabled()) {
	log.debug("Unable to get Common Name - " + e);
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("AddName: " + principal.getName());
    }

    Hashtable principals = (Hashtable)cn2dn.get(cn);
    // Can have more than one dn with the same cn with multiple CA
    /* Since the common name must currently be unique, it is a configuration
     * error if two distinguished names have the same common name. */
      /*
    if (aPrincipal != null &&
	!aPrincipal.equals(x500Name)) {
      // Cannot continue. Configuration error.
      throw new IllegalArgumentException("Two DNs have same CN. Keeping "
					 + x500Name + " - "
					 + aPrincipal.toString() + " excluded");
                                         */
    if (principals == null) {
      principals = new Hashtable();
      cn2dn.put(cn, principals);
    }

    // This is to improve the performance if searching for x500name
    // if use List X500Name comparison is very time consuming.
    principals.put(x500Name.getName(), x500Name);
  }

  public List getX500Name(String commonName) {
    List nameList = new ArrayList();
    Hashtable principals = (Hashtable)cn2dn.get(commonName);
    if (principals != null) {
      nameList.addAll(principals.values());
    }
    return nameList;
  }

  public boolean contains(X500Name dname) {
    Hashtable principals = null;
    try {
      principals = (Hashtable)cn2dn.get(dname.getCommonName());
    }
    catch (IOException iox) {
      if (log.isWarnEnabled()) {
        log.warn("Cannot get Common name: " + dname);
      }
    }
    if (principals != null) {
      return (principals.get(dname.getName()) != null);
    }
    return false;
  }
}
