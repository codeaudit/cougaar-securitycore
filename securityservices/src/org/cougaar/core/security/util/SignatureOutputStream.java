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

import java.util.*;
import java.io.*;
import java.security.*;

public class SignatureOutputStream extends FilterOutputStream {
  Signature _signature;
  public SignatureOutputStream(OutputStream os, String algorithm, 
                               PrivateKey signKey) 
    throws NoSuchAlgorithmException, InvalidKeyException {
    super(os);
    _signature = Signature.getInstance(algorithm);
    _signature.initSign(signKey);
  }

  public void write(byte[] b) throws IOException {
    super.write(b);
    try {
      _signature.update(b);
    } catch (SignatureException e) {
      // never happens... we initialize properly always
    }
  }

  public void write(byte[] b, int off, int len) throws IOException {
    super.write(b, off, len);
    try {
      _signature.update(b, off, len);
    } catch (SignatureException e) {
      // never happens... we initialize properly always
    }
  }

  public void write(byte b) throws IOException {
    super.write(b);
    try {
      _signature.update(b);
    } catch (SignatureException e) {
      // never happens... we initialize properly always
    }
  }

  public void writeSignature() throws IOException {
    try {
      byte[] sig = _signature.sign();
      int len = sig.length;
      int sigTop = (len & 0xFF00) >> 8;
      int sigBottom = len & 0x00FF;
      super.write(sigTop);
      super.write(sigBottom);
      super.write(sig);
    } catch (SignatureException e) {
      // will never happen
    }
  }
}
