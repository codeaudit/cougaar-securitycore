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

  private DataProtectionKeyImpl finalKey;
  private String agent;

  private InputStream plainStream;

  public DataProtectionInputStream(InputStream is,
    DataProtectionKey dpkey, String agent, ServiceBroker sb)
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

    finalKey = (DataProtectionKeyImpl)dpkey;
    this.agent = agent;

    plainStream = processStream(is);
  }

  public int available()
    throws IOException
  {
    return plainStream.available();
  }

  public int read()
    throws IOException
  {
    return plainStream.read();
  }

  public void close()
    throws IOException
  {
    // clean up?
    plainStream.close();
    super.close();
  }

  public void mark(int readlimit) {
    plainStream.mark(readlimit);
  }

  public boolean markSupported() {
    return plainStream.markSupported();
  }

  public long skip(long n)
    throws IOException
  {
    return plainStream.skip(n);
  }

  public void reset()
    throws IOException
  {
    plainStream.reset();
  }

  public int read(byte [] bytes)
    throws IOException
  {
    return plainStream.read(bytes);
  }

  public int read(byte [] bytes, int offset, int len)
    throws IOException
  {
    return plainStream.read(bytes, offset, len);
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
    MessageDigest md = null;
    ByteArrayOutputStream plainbytes = new ByteArrayOutputStream();
    ByteArrayOutputStream extrabytes = new ByteArrayOutputStream();
    byte [] rbytes = new byte[2000];

    byte [] prefix = DataProtectionOutputStream.strPrefix.getBytes();
    while (is.available() > 0) {
      // get encrypted stream
      InputStream encryptedStream = getEncryptedStream(is, extrabytes, prefix);
      // get signed object
      SignedObject sobj = getSignedObject(is, extrabytes);

      // verify signed object
      DataProtectionKeyImpl dpKey = null;
      try {
        dpKey = (DataProtectionKeyImpl)sobj.getObject();
      } catch (Exception ex) {
        throw new IOException("Cannot get object.");
      }
      SecureMethodParam policy = dpKey.getSecureMethod();
      encryptionService.verify(agent, policy.signSpec, sobj);

      // get digest stream
      if (md == null)
        md = MessageDigest.getInstance(dpKey.getDigestAlg());
      DigestInputStream dis = new DigestInputStream(encryptedStream, md);
      FilterInputStream theis = dis;

      // decrypt stream
      if (policy.secureMethod == SecureMethodParam.ENCRYPT
        || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
        // unprotect key
        SecretKey skey = (SecretKey)encryptionService.asymmDecrypt(agent,
          policy.asymmSpec, dpKey.getSecretKey());
        Cipher ci=Cipher.getInstance(policy.symmSpec);
        ci.init(Cipher.DECRYPT_MODE,skey);
        theis = new CipherInputStream(theis, ci);
      }
      while (true) {
        int result = theis.read(rbytes);
        if (result == -1)
          break;
        plainbytes.write(rbytes, 0, result);
      }

      // update md and compare with encrypted stream digest
      md = dis.getMessageDigest();
      if (!MessageDigest.isEqual(md.digest(), dpKey.getDigest()))
        throw new GeneralSecurityException("Digest does not match.");
    }

    // update dpkey
    //finalKey.setDigest(md.digest());
    return new ByteArrayInputStream(plainbytes.toByteArray(), 0, plainbytes.size());
  }

  private SignedObject getSignedObject(InputStream is, ByteArrayOutputStream extrabytes)
    throws IOException
  {
    encrypt = false;
    byte [] postfix = DataProtectionOutputStream.strPostfix.getBytes();
    InputStream sis = getEncryptedStream(is, extrabytes, postfix);
    ObjectInputStream ois = new ObjectInputStream(sis);
    SignedObject sobj = null;
    try {
      sobj = (SignedObject)ois.readObject();
    } catch (Exception ex) {
      throw new IOException("Cannot retrieve signed object");
    }
    return sobj;
  }

  boolean encrypt = true;

  private InputStream getEncryptedStream(InputStream is, ByteArrayOutputStream extrabytes, byte [] prefix)
    throws IOException
  {
    // array to read bytes
    byte [] rbytes = new byte[2000];
    // array to hold bytes read
    ByteArrayOutputStream barray = new ByteArrayOutputStream();

    // get the extra bytes
    byte [] exbytes = extrabytes.toByteArray();
    for (int i = 0; i < exbytes.length; i++)
      rbytes[i] = exbytes[i];

    // result of the current read, num of bytes read or -1 if failed
    int result = exbytes.length;

    int carryover = 0;
    while (true) {
      if (carryover != 0) {
        int limit = prefix.length - carryover;
        int j = 0;
        for (; j < limit; j++) {
          if (prefix[j + carryover] != rbytes[j])
            break;
        }
        if (j != limit) {
          extrabytes.write(rbytes, limit, result - limit);
          break;
        }
        else {
          // dont lose those carryover bytes
          barray.write(prefix, 0, carryover);
        }
      }

      // read the signature
      int sstart = findSignature(rbytes, 0, result, prefix);
      carryover = 0;
      if (sstart != -1) {
        int sgap = result - sstart;
        // handle boundary condition
        if (sgap < prefix.length)
          carryover = prefix.length - sgap;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(rbytes, sstart, (carryover == 0) ? prefix.length : sgap);
        //System.out.println("signature: " + new String(bos.toByteArray()));
      }
      //System.out.println("read: " + result + " : " + sstart + " : " + carryover);

      barray.write(rbytes, 0, ((sstart == -1) ? result : sstart));

      if (sstart != -1 && carryover == 0) {
        extrabytes.reset();
        int offset = sstart + prefix.length;
        extrabytes.write(rbytes, offset, result - offset);
        break;
      }

      result = is.read(rbytes);
      if (result == -1)
        throw new IOException("Unexpected end of file for encrypted stream.");
    }

    // pack up the stream and return

    return new ByteArrayInputStream(barray.toByteArray(), 0, barray.size());
  }

  private int findSignature(byte [] rbytes, int start, int end, byte [] signature) {
    for (int i = start; i < end; i++) {
      if (rbytes[i] != signature[0])
        continue;

      // check array out of bounce
      int limit = end - i;
      if (limit > signature.length)
        limit = signature.length;
      int j = 1;
      for (; j < limit; j++)
        if (signature[j] != rbytes[i + j])
          break;

      if (j == limit)
        return i;
    }
    return -1;
  }

  public static String testFileName;
}
