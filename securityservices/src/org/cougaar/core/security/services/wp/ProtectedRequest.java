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



package org.cougaar.core.security.services.wp;


import org.cougaar.core.service.wp.WhitePagesProtectionService;

import java.security.SignedObject;
import java.security.cert.X509Certificate;


/**
 * A wrapped request object containing the a signed request object with its
 * certificate chain
 *
 * @author mabrams
 */
public class ProtectedRequest implements WhitePagesProtectionService.Wrapper {
  private X509Certificate[] certificateChain = null;
  private SignedObject signedObject = null;

  /**
   * Creates a new ProtectedRequest object.
   *
   * @param chain the certificate chain
   * @param signed the signed object
   */
  public ProtectedRequest(X509Certificate[] chain, SignedObject signed) {
    this.certificateChain = chain;
    this.signedObject = signed;
  }

  /**
   * @see org.cougaar.core.security.services.wp.Wrapper#getSignedObject()
   */
  public SignedObject getSignedObject() {
    return signedObject;
  }


  /**
   * @see org.cougaar.core.security.services.wp.Wrapper#setSignedObject()
   */
  public void setSignedObject(SignedObject signedObj) {
    this.signedObject = signedObj;
  }


  /**
   * @see org.cougaar.core.security.services.wp.Wrapper#getCertificateChain()
   */
  public X509Certificate[] getCertificateChain() {
    return certificateChain;
  }


  /**
   * @see org.cougaar.core.security.services.wp.Wrapper#setCertificateChain(java.security.cert.X509Certificate[])
   */
  public void setCertificateChain(X509Certificate[] certChain) {
    this.certificateChain = certChain;
  }
}
