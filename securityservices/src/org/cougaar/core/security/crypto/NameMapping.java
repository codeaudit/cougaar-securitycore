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

    /* Since the common name must currently be unique, it is a configuration
     * error if two distinguished names have the same common name. */
    synchronized(this) {
      X500Name aPrincipal = (X500Name)cn2dn.get(cn);
      if (aPrincipal != null &&
	  !aPrincipal.equals(x500Name)) {
	// Cannot continue. Configuration error.
	throw new IllegalArgumentException("Two DNs have same CN. Keeping "
					   + x500Name + " - "
					   + aPrincipal.toString() + " excluded");
      }
      cn2dn.put(cn, x500Name);
    }
  }

  public X500Name getX500Name(String commonName) {
    X500Name name = (X500Name) cn2dn.get(commonName);
    return name;
  }
}
