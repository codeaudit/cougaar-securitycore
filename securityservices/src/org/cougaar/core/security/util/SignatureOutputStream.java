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
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

public class SignatureOutputStream
  extends DigestOutputStream
  implements SignedDigestOutputStream
{
  private Signature _signature;
  private OutputStream _os;

  public SignatureOutputStream(OutputStream os, String algorithm, 
                               PrivateKey signKey) 
    throws NoSuchAlgorithmException, InvalidKeyException {
    super(os, MessageDigest.getInstance("SHA"));
    _os = os;
    _signature = Signature.getInstance(algorithm);
    _signature.initSign(signKey);
  }

  public byte[] writeSignature() throws IOException {
    try {
      byte[] digest = getMessageDigest().digest();
      _signature.update(digest);

      byte[] sig = _signature.sign();
      int len = sig.length;
      int sigTop = (len & 0xFF00) >> 8;
      int sigBottom = len & 0x00FF;
      super.write(sigTop);
      super.write(sigBottom);
      super.write(sig);
      return sig;
    } catch (SignatureException e) {
      // will never happen
      throw new IOException("Failed to get signature: " + e.toString());
    }
  }

}
