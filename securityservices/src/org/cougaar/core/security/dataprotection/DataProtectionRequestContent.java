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


package org.cougaar.core.security.dataprotection;

import java.io.Serializable;
import java.security.cert.X509Certificate;

/**
 * The content of the request that goes from the Data Protection service to the
 * Persistence Management Agent.
 */
public class DataProtectionRequestContent implements Serializable
{
  /** The collection of keys that were used to encrypt the persisted blackboard. */
  private DataProtectionKeyCollection keyCollection;

  /** The certificate chain of the entity which asks to unlock the key. */
  private X509Certificate[] requestorCertificateChain;

  public DataProtectionRequestContent(DataProtectionKeyCollection kc,
				      X509Certificate[] certChain) {
    keyCollection = kc;
    requestorCertificateChain = certChain;
  }

  /** Return the collection of keys that were used to encrypt the persisted blackboard. */
  public DataProtectionKeyCollection getKeyCollection() {
    return keyCollection;
  }

  /** Return the certificate chain of the entity which asks to unlock the key. */
  public X509Certificate[] getRequestorCertificateChain() {
    return requestorCertificateChain;
  }
}
