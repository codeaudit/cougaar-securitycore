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
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.identity.TransferableIdentity;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class KeyWrapping
{
  private EncryptionService encryptionService;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  public KeyWrapping(ServiceBroker sb)
  {
    // TODO: use service broker
    encryptionService = null;

    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
  }

  /** @param privKey        The private keys to wrap
   *  @param cert           The certificates to wrap
   *  @param signerPrivKey  The private key of the signer
   *  @param signerCert     The certificate of the signer
   *  @param rcvrCert       The certificate of the intended receiver
   */
  public TransferableIdentity protectPrivateKey(PrivateKey[] privKey,
						X509Certificate[] cert,
						PrivateKey signerPrivKey,
						X509Certificate signerCert,
						X509Certificate rcvrCert)
  {
    if (log.isDebugEnabled()) {
      log.debug("Wrapping keys");
    }

    KeyIdentity keyIdentity = null;

    KeySet keySet = new KeySet(privKey, cert);
    MessageAddress sourceAgent = null;
    MessageAddress targetAgent = null;
    SecureMethodParam policy = null;
    try {
      encryptionService.protectObject(keySet,
				      sourceAgent, targetAgent,
				      policy);
    }
    catch (GeneralSecurityException e) {
    }
    catch (IOException e) {
    }
    return keyIdentity;
  }

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private key of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  public TransferableIdentity getPfx(byte[] pfxBytes,
				     PrivateKey rcvrPrivKey,
				     Certificate rcvrCert)
  {
    KeyIdentity keyIdentity = null;
    return keyIdentity;
  }
}
