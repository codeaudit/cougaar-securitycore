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


package org.cougaar.core.security.util;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class SignatureInputStream
  extends DigestInputStream
  implements SignedDigestInputStream
{
  private Signature _signature;
  private InputStream _is;

  public SignatureInputStream(InputStream is, String algorithm, 
                              PublicKey pubKey) 
    throws NoSuchAlgorithmException, InvalidKeyException {
    super(is, MessageDigest.getInstance("SHA"));
    _is = is;
    _signature = Signature.getInstance(algorithm);
    _signature.initVerify(pubKey);
  }

  public void verifySignature()
    throws IOException, SignatureException {

    byte[] digest = getMessageDigest().digest();
    _signature.update(digest);

    int sigTop = super.read();
    if (sigTop == -1) {
      throw new SignatureException("No signature available");
    }
    int sigBottom = super.read();
    if (sigBottom == -1) {
      throw new SignatureException("No signature available");
    }
    int len = ((sigTop & 0xFF) << 8) | (sigBottom & 0xFF);

    byte[] sig = new byte[len];
    int bytesRead;
    int offset = 0;
    do {
      bytesRead = super.read(sig, offset, sig.length - offset);
      if (bytesRead == -1) {
        throw new SignatureException("No signature available");
      }
      offset += bytesRead;
    } while (offset < sig.length);
    _signature.verify(sig);
  }
}
