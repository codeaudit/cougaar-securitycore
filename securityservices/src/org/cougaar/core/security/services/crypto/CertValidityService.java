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


package org.cougaar.core.security.services.crypto;

import org.cougaar.core.component.Service;
import org.cougaar.core.security.crypto.CertValidityListener;
import org.cougaar.core.security.policy.TrustedCaPolicy;

import sun.security.x509.X500Name;

public interface CertValidityService extends Service {
// will make the certificate if it is not present, this should only be used for local agents!
  public void addValidityListener(CertValidityListener listener);

  public void updateCertificate(String commonName);

  public void invalidate(String cname);

// only listen when cert becomes invalid, does not check and make cert, there is a possibility that the agent is NOT local
// used for messaging or ssl
  public void addInvalidateListener(CertValidityListener listener);

// only listens when a cert becomes available, does not check make the cert if it is not available. there is a possibility that the agent is NOT local
// used for name server certificate update
  public void addAvailabilityListener(CertValidityListener listener);

// check if the (local) agent has been revoked
  public boolean isInvalidated(String commonName);

  public void addCertRequest(X500Name dname, boolean isCA, TrustedCaPolicy tcp);
}

