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

public class DataProtectionInputStream extends FilterInputStream {
  private LoggingService log;
  private ServiceBroker serviceBroker;
  private EncryptionService encryptionService;

  private DataProtectionKeyImpl dpKey;
  private String agent;

  private MessageDigest md = null;
  private Cipher ci = null;
  private SecureMethodParam policy = null;

  private InputStream theis = null;
  private static int skiplimit = 2000;

  public DataProtectionInputStream(InputStream is,
    DataProtectionKeyEnvelope keyEnv, String agent, ServiceBroker sb)
    throws GeneralSecurityException, IOException {
    super(is);

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

    dpKey = (DataProtectionKeyImpl)keyEnv.getDataProtectionKey();
    policy = dpKey.getSecureMethod();

    this.agent = agent;

    theis = processStream(is);
  }

  public int available()
    throws IOException
  {
    // for cipher stream this does not seem to be returning anything
    return theis.available();
  }

  public int read()
    throws IOException
  {
    return read(new byte[1], 0, 1);
  }

  public void close()
    throws IOException
  {
    // clean up?
    super.close();
  }

  public void mark(int readlimit) {
    theis.mark(readlimit);
  }

  public boolean markSupported() {
    return theis.markSupported();
  }

  public long skip(long n)
    throws IOException
  {
    // do not support skip if it is a cipher stream
    long skiplen = 0L;
    while (n > 0) {
      int result = read(null, 0, skiplimit);
      if (result == -1)
        break;
      n -= result;
      skiplen += result;
    }
    return skiplen;
  }

  public void reset()
    throws IOException
  {
    theis.reset();
  }

  public int read(byte [] bytes)
    throws IOException
  {
    return read(bytes, 0, bytes.length);
  }

  public int read(byte [] bytes, int offset, int len)
    throws IOException
  {
    // this function does not attempt to read all the len data
    // but will read til the end of the current chunk, then
    // the next read will handle the rest

    int result = theis.read(bytes, offset, len);

    // getting next chunk of data
    if (result == -1) {
      try {
        theis.close();
        theis = processStream(in);
        if (theis == null) {
          // create empty stream so that other calls won't
          // get null pointer
          theis = new ByteArrayInputStream(new byte[] {});
          return -1;
        }

        result = theis.read(bytes, offset, len);
      } catch (GeneralSecurityException gse) {
        throw new IOException(gse.toString());
      }
    }

    return result;
  }

  private void initStream()
    throws GeneralSecurityException
  {
    md = MessageDigest.getInstance(dpKey.getDigestAlg());
    if (policy.secureMethod == SecureMethodParam.ENCRYPT
      || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      // unprotect key
      SecretKey skey = getSecretKey();
      ci=Cipher.getInstance(policy.symmSpec);
      ci.init(Cipher.DECRYPT_MODE,skey);
    }
  }

  private SecretKey getSecretKey()
    throws CertificateException
  {
    return (SecretKey)encryptionService.asymmDecrypt(agent,
        policy.asymmSpec, (SealedObject)dpKey.getObject());
  }

  /**
   * This function
   *  1. reads encrypted stream
   *  2. get digest algorithm and compute digest while getting the signature
   *  3. compare signature
   *  4. return decipher byte stream
   *
   *  issues:
   *  . available is not checked, this may cause boundary conditions to
   *    occur and the module assumes all bytes are read. The module will
   *    not find the signature it is looking for, and throws exception.
   */
  private InputStream processStream(InputStream is)
    throws IOException, GeneralSecurityException
  {
    if (is.available() == 0)
      return null;

    initStream();
    byte [] rbytes = new byte[2000];

    /*
    int read = is.read(rbytes, 0, DataProtectionOutputStream.strPrefix.length());
    System.out.println("Read:" + new String(rbytes, 0, read));
    */

    DataProtectionDigestObject dobj = (DataProtectionDigestObject)getSignedObject(is);

    int totalBytes = dobj.getEncryptedSize();
    ByteArrayOutputStream bos = new ByteArrayOutputStream();

    while (totalBytes > 0) {
      int result = (totalBytes > rbytes.length) ? rbytes.length : totalBytes;
      result = is.read(rbytes, 0, result);

      if (result == -1) {
        throw new IOException("Unexpected end of file");
      }
      totalBytes -= result;
      bos.write(rbytes, 0, result);
    }

    InputStream dis = new ByteArrayInputStream(bos.toByteArray());
    if (ci != null)
      dis = new CipherInputStream(dis, ci);
    // get digest stream
    dis = new DigestInputStream(dis, md);

    /*
    byte [] bout = bos.toByteArray();
    return new ByteArrayInputStream(bout, 0, bout.length);
    */
    return dis;
  }

  private Object getSignedObject(InputStream is)
    throws IOException, GeneralSecurityException
  {
    // verify signed object
    try {
      ObjectInputStream ois = new ObjectInputStream(is);
      SealedObject sealedObj = (SealedObject)ois.readObject();
      //System.out.println("signedObject: " + sealedObj);
      SecretKey skey = getSecretKey();
      SignedObject sobj = (SignedObject)
        encryptionService.symmDecrypt(skey, sealedObj);
      Object obj = encryptionService.verify(agent, policy.signSpec, sobj);
      if (obj == null)
        throw new GeneralSecurityException("Cannot verify signature.");
      return obj;
    } catch (ClassNotFoundException ex) {
      throw new IOException("Cannot retrieve object" + ex.toString());
    }
  }

  public static String testFileName;
}