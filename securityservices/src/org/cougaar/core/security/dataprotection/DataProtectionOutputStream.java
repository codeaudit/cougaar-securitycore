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

  private String agent;
  private SecureMethodParam policy;
  private DataProtectionKeyImpl dpKey;
  private Cipher ci;
  private ObjectOutputStream oos;

  public static final String strPrefix = "--SIGNATUREBEGIN--";
  public static final String strPostfix = "--SIGNATUREEND--";

  /**
   * buffer size, when reached will flush to output stream
   */
  private static int buffersize = 30000;
  private ByteArrayOutputStream bos = new ByteArrayOutputStream();
  private OutputStream theos = null;
  private int totalBytes = 0;

  public DataProtectionOutputStream(OutputStream os,
    DataProtectionKeyEnvelope pke, String agent, ServiceBroker sb)
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

    this.agent = agent;

    dpKey = (DataProtectionKeyImpl)pke.getDataProtectionKey();
    policy = dpKey.getSecureMethod();
    // unprotect key
    SecretKey skey = getSecretKey();
    String digestAlg = dpKey.getDigestAlg();

    // encrypt stream
    theos = bos;
    if (policy.secureMethod == SecureMethodParam.ENCRYPT
      || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      //Cipher ci=Cipher.getInstance(policy.symmSpec);
      ci = encryptionService.getCipher(policy.symmSpec);
      ci.init(Cipher.ENCRYPT_MODE,skey);
      theos = new CipherOutputStream(theos, ci);
    }

    MessageDigest md = MessageDigest.getInstance(digestAlg);
    theos = new DigestOutputStream(theos, md);
    oos = new ObjectOutputStream(out);

    System.out.println("Opening output stream " + agent + " : " + new Date());
  }

  private SecretKey getSecretKey()
    throws CertificateException
  {
    return (SecretKey)encryptionService.asymmDecrypt(agent,
      policy.asymmSpec, (SealedObject)dpKey.getObject());
  }

  public void close() throws IOException {
    System.out.println("Closing output stream " + new Date());
    flushToOutput(true);

    if (ci != null)
      encryptionService.returnCipher(policy.symmSpec, ci);
    super.close();
  }

  public void flush() throws IOException {
    // data is stored in memory, does not get flushed out until limit reached
  }

  public void flushToOutput(boolean genDigest) throws IOException {
    // close output stream so that cipher can be completed
    theos.close();

    // use this as a marker
    //out.write(strPrefix.getBytes());
    oos.writeInt(bos.size());
    oos.writeInt(genDigest ? 1 : 0);
    oos.flush();

    bos.writeTo(out);
    bos.reset();

    if (genDigest) {
      // generate digest and sign
      MessageDigest md = ((DigestOutputStream)theos).getMessageDigest();
      try {
        Serializable sobj = new DataProtectionDigestObject(md.digest(), totalBytes);
        if (policy.secureMethod == SecureMethodParam.SIGN
          || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
          sobj = encryptionService.sign(agent, policy.signSpec, sobj);
        }
        if (policy.secureMethod == SecureMethodParam.ENCRYPT
          || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
          SecretKey skey = getSecretKey();
          sobj = encryptionService.symmEncrypt(skey, policy.symmSpec, sobj);
        }
        oos.writeObject(sobj);
        oos.flush();
      } catch (GeneralSecurityException ex) {
        throw new IOException("Cannot sign digest: " + ex.toString());
      }

    }
  }

  public void write(byte[] b) throws IOException {
    write(b, 0, b.length);
  }

  public void write(int b) throws IOException {
    theos.write(b);
  }

  public void write(byte[] b, int off, int len) throws IOException {
    // update cipher
    totalBytes += len;
    theos.write(b, off, len);
    if (bos.size() > buffersize)
      flushToOutput(false);
  }

  public static int getBufferSize() {
    return buffersize;
  }

  public static void setBufferSize(int size) {
    buffersize = size;
  }
}