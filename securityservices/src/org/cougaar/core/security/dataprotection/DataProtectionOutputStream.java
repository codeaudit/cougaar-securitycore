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

import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.security.cert.*;

// Cougaar core infrastructure
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

// overlay
import org.cougaar.core.service.*;

// Security Service
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.crypto.*;

public class DataProtectionOutputStream extends FilterOutputStream {
  private LoggingService log;
  private ServiceBroker serviceBroker;
  private EncryptionService encryptionService;

  private DataProtectionKeyImpl dpKey;
  private String agent;
  private FilterOutputStream theos;
  private OutputStream os;

  public static final String strPrefix = "--SIGNATUREBEGIN--";
  public static final String strPostfix = "--SIGNATUREEND--";

  public DataProtectionOutputStream(OutputStream os,
    DataProtectionKey dpkey, String agent, ServiceBroker sb)
    throws GeneralSecurityException, IOException {
    super(os);

    serviceBroker = sb;
    // Get encryption service
    encryptionService = (EncryptionService)
      serviceBroker.getService(this,
			       EncryptionService.class,
			       null);
    if (encryptionService == null) {
       throw new RuntimeException("Encryption service not available");
    }

    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    this.dpKey = (DataProtectionKeyImpl)dpkey;
    this.agent = agent;

    SecureMethodParam policy = dpKey.getSecureMethod();
    // unprotect key
    SecretKey skey = (SecretKey)encryptionService.asymmDecrypt(agent,
      policy.asymmSpec, dpKey.getSecretKey());

    this.os = os;

    // encrypt stream
    if (policy.secureMethod == SecureMethodParam.ENCRYPT
      || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      Cipher ci=Cipher.getInstance(policy.symmSpec);
      ci.init(Cipher.ENCRYPT_MODE,skey);
      theos = new CipherOutputStream(os, ci);
    }

    MessageDigest md = MessageDigest.getInstance(dpKey.getDigestAlg());

    // generate digest stream on top of cipher stream
    if (theos != null)
      theos = new DigestOutputStream(theos, md);
    else
      theos = new DigestOutputStream(os, md);
  }

  public void close() throws IOException {

    // generate digest and sign
    MessageDigest md = ((DigestOutputStream)theos).getMessageDigest();
    // update DataProtectionKey
    dpKey.setDigest(md.digest());
    SignedObject sobj = null;
    try {
      sobj = encryptionService.sign(agent, dpKey.getSecureMethod().signSpec, dpKey);
    } catch (GeneralSecurityException ex) {
      if (log.isDebugEnabled())
        log.warn("Cannot sign digest: " + ex.toString());
    }

    // write prefix
    os.write(strPrefix.getBytes());

    // write the signed digest to outputstream
    ObjectOutputStream oos = new ObjectOutputStream(os);
    oos.writeObject(sobj);
    oos.flush();

    // write postfix
    os.write(strPostfix.getBytes());

    super.close();
  }

  public void flush() throws IOException {
    // encrypt the part to be flushed
    theos.flush();
  }

  public void write(byte[] b) throws IOException {
    write(b, 0, b.length);
  }

  public void write(int b) throws IOException {
    theos.write(b);
  }

  public void write(byte[] b, int off, int len) throws IOException {
    // update cipher
    theos.write(b, off, len);
  }

}
