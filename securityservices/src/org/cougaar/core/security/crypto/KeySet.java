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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/** This class contains the list of private keys and public keys
 *  that should be moved when an agent moves.
 */
public class KeySet
  implements java.io.Serializable
{
  private PrivateKey[]  privateKeys;
  private X509Certificate[] certificates;

  public KeySet(PrivateKey[] privateKeys,
		X509Certificate[] certificates) {
    if ((privateKeys == null) || (privateKeys.length ==0) ||
	(certificates == null) || (certificates.length == 0)) {
      throw new IllegalArgumentException("Keys are not provided");
    }
    
    /*
     * It is actually OK to have a different number of public and private keys
    if (privateKeys.length != certificates.length) {
      throw new
	IllegalArgumentException("Number of keys and certs do not match");
    }
    */

    this.privateKeys = privateKeys;
    this.certificates = certificates;
  }

  public PrivateKey[] getPrivateKeys() {
    return privateKeys;
  }

  public X509Certificate[] getCertificates() {
    return certificates;
  }
}
