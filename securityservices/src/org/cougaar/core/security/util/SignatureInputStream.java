/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * Created on September 12, 2001, 10:55 AM
 */

package org.cougaar.core.security.util;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.DigestInputStream;
import java.security.MessageDigest;
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
