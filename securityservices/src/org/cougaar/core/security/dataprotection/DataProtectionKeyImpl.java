/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */

package org.cougaar.core.security.dataprotection;

import javax.crypto.*;
import java.security.*;
import java.io.*;
import java.util.*;

// overlay
import org.cougaar.core.service.*;

// Security Services
import org.cougaar.core.security.crypto.*;

public class DataProtectionKeyImpl extends ProtectedObject
  implements DataProtectionKey {
  private String digestAlgSpec;
  private byte[] digest;

  public DataProtectionKeyImpl(SealedObject secretKey,
      String digestAlg, SecureMethodParam policy) {
    super(policy, secretKey);
    digestAlgSpec = digestAlg;
  }

  public SealedObject getSecretKey() {
    return (SealedObject)getObject();
  }

  public String getDigestAlg() {
    return digestAlgSpec;
  }

  public byte[] getDigest() {
    return digest;
  }

  public void setDigest(byte[] digest) {
    this.digest = digest;
  }
}