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
import java.security.Signature;
import java.security.SignatureException;

public class SignatureInputStream extends FilterInputStream {
  Signature _signature;
  public SignatureInputStream(InputStream os, String algorithm, 
                              PublicKey pubKey) 
    throws NoSuchAlgorithmException, InvalidKeyException {
    super(os);
    _signature = Signature.getInstance(algorithm);
    _signature.initVerify(pubKey);
  }

  public int read() throws IOException {
    int b = super.read();
    if (b != -1) {
      try {
        _signature.update((byte) b);
      } catch (SignatureException e) {
        // never happens... we initialize properly always
      }
    }
    return b;
  }

  public int read(byte[] b, int off, int len) throws IOException {
    int count = super.read(b, off, len);
    try {
      _signature.update(b, off, count);
    } catch (SignatureException e) {
      // never happens... we initialize properly always
    }
    return count;
  }

  public int read(byte[] b) throws IOException {
    int count = super.read(b);
    try {
      _signature.update(b, 0, count);
    } catch (SignatureException e) {
      // never happens... we initialize properly always
    }
    return count;
  }

  public void verifySignature() throws IOException, SignatureException {
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
