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
  private DataProtectionDigestObject dobj = null;
  private static int skiplimit = 2000;

  private byte [] rbytes = new byte[2000];

  private SecretKey skey = null;
  private ByteArrayOutputStream bos = new ByteArrayOutputStream();

  public DataProtectionInputStream(InputStream is,
    DataProtectionKeyEnvelope pke,
    String agent,
    ServiceBroker sb)
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

    this.agent = agent;
    try {
      dpKey = (DataProtectionKeyImpl)pke.getDataProtectionKey();
    } catch (Exception ex) {
    }
    if (dpKey == null)
      throw new GeneralSecurityException("No data protection key present.");
    policy = dpKey.getSecureMethod();
    skey = getSecretKey();
    md = MessageDigest.getInstance(dpKey.getDigestAlg());
    if (policy.secureMethod == SecureMethodParam.ENCRYPT
      || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      //ci=Cipher.getInstance(policy.symmSpec);
      ci=encryptionService.getCipher(policy.symmSpec);
    }

    System.out.println("Opening inputStream: " + agent + " : " + new Date());
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
    int result = theis.read();

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

        result = theis.read();
      } catch (GeneralSecurityException gse) {
        throw new IOException(gse.toString());
      }
    }

    return result;
  }

  public void close()
    throws IOException
  {
    // clean up?
    System.out.println("Closing inputStream " + new Date());

    verifyDigest();
    if (ci != null)
      encryptionService.returnCipher(policy.symmSpec, ci);
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

    //System.out.println("read: " + len + " : " + result);
    return result;
  }

  private SecretKey getSecretKey()
    throws CertificateException
  {
    return (SecretKey)encryptionService.asymmDecrypt(agent,
        policy.asymmSpec, (SealedObject)dpKey.getObject());
  }

  private void verifyDigest()
    throws IOException
  {
    if (dobj != null) {
      md = ((DigestInputStream)theis).getMessageDigest();
      // reset so that digest does not get updated
      theis = null;
      if (!MessageDigest.isEqual(dobj.getDigest(), md.digest()))
        throw new IOException("Digest does not match");
      if (log.isDebugEnabled())
        log.debug("Decrypt successful, digest matching.");
      dobj = null;
    }

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
    //verify digest
    verifyDigest();

    if (is.available() == 0)
      return null;

    /*
    int read = is.read(rbytes, 0, DataProtectionOutputStream.strPrefix.length());
    System.out.println("Read:" + new String(rbytes, 0, read));
    */

    //dobj = (DataProtectionDigestObject)getSignedObject(is);

    //int totalBytes = dobj.getEncryptedSize();
    ObjectInputStream ois = new ObjectInputStream(is);
    int totalBytes = ois.readInt();
    int readDigest = ois.readInt();

    bos.reset();
    while (totalBytes > 0) {
      int result = (totalBytes > rbytes.length) ? rbytes.length : totalBytes;
      result = is.read(rbytes, 0, result);

      if (result == -1) {
        throw new IOException("Unexpected end of file");
      }
      totalBytes -= result;
      bos.write(rbytes, 0, result);
    }

    // digest is at the end of the whole stream
    if (readDigest == 1)
      dobj = (DataProtectionDigestObject)getSignedObject(is);
    //System.out.println("digest: " + readDigest + " : " + dobj);

    InputStream dis = new ByteArrayInputStream(bos.toByteArray());
    if (ci != null) {
      ci.init(Cipher.DECRYPT_MODE,skey);
      dis = new CipherInputStream(dis, ci);
    }
    // get digest stream
    if (theis != null) {
      md = ((DigestInputStream)theis).getMessageDigest();
    }

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
      Object sobj = (Serializable)ois.readObject();
      //SecretKey skey = getSecretKey();
      if (policy.secureMethod == SecureMethodParam.ENCRYPT
        || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
        sobj = encryptionService.symmDecrypt(skey, (SealedObject)sobj);
        if (sobj == null)
          throw new GeneralSecurityException("Invalid private key");
      }
      if (policy.secureMethod == SecureMethodParam.SIGN
        || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
        sobj = encryptionService.verify(agent, policy.signSpec,
          (SignedObject)sobj, true);
        if (sobj == null)
          throw new GeneralSecurityException("Cannot verify signature.");
      }
      return sobj;
    } catch (ClassNotFoundException ex) {
      throw new IOException("Cannot retrieve object" + ex.toString());
    }
  }

  public static String testFileName;
}
