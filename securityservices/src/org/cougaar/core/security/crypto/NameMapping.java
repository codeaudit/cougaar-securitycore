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


package org.cougaar.core.security.crypto;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import sun.security.x509.X500Name;

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
    synchronized(this) {
      if (principals == null) {
	principals = new Hashtable();
	cn2dn.put(cn, principals);
      }
      // This is to improve the performance if searching for x500name
      // if use List X500Name comparison is very time consuming.
      principals.put(x500Name.getName(), x500Name);
    }
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
