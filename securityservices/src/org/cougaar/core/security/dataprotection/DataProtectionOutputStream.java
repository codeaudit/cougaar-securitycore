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
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.DataFailureEvent;

public class DataProtectionOutputStream extends FilterOutputStream {
  private LoggingService log;
  private ServiceBroker serviceBroker;
  private EncryptionService encryptionService;

  private String agent;
  private SecureMethodParam policy;
  private DataProtectionKeyImpl dpKey;
  private Cipher ci;
  
  public static final String strPrefix = "--SIGNATUREBEGIN--";
  public static final String strPostfix = "--SIGNATUREEND--";

  /**
   * buffer size, when reached will flush to output stream
   */
  private static int buffersize = 30000;
  private ByteArrayOutputStream bos = new ByteArrayOutputStream();
  private OutputStream theos = null;
  private int totalBytes = 0;
  private boolean debug = false;
  
  // used to publish data failures
  private EventPublisher eventPublisher;

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
		if(log != null) {
      debug = log.isDebugEnabled();
    }
    this.agent = agent;

    dpKey = (DataProtectionKeyImpl)pke.getDataProtectionKey();
    if (dpKey == null) {
      GeneralSecurityException gsx = 
        new GeneralSecurityException("No data protection key present.");
      publishDataFailure(DataFailureEvent.NO_KEYS, gsx.toString());
      throw gsx;
    }
    policy = dpKey.getSecureMethod();
    String digestAlg = dpKey.getDigestAlg();

    // encrypt stream
    theos = bos;
    
    if (policy.secureMethod == SecureMethodParam.ENCRYPT
      || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      // unprotect key
      String failureIfOccurred = DataFailureEvent.UNKNOWN_FAILURE;
      SecretKey skey = null;
      try {
        failureIfOccurred = DataFailureEvent.SECRET_KEY_FAILURE;
        skey = getSecretKey();
      //Cipher ci=Cipher.getInstance(policy.symmSpec);
        failureIfOccurred = DataFailureEvent.INVALID_POLICY;
        ci = encryptionService.getCipher(policy.symmSpec);
      }
      catch(GeneralSecurityException gsx) {
        publishDataFailure(failureIfOccurred, gsx.toString());
        throw gsx; 
      }
      ci.init(Cipher.ENCRYPT_MODE,skey);
      theos = new CipherOutputStream(theos, ci);
    }

    MessageDigest md = MessageDigest.getInstance(digestAlg);
    theos = new DigestOutputStream(theos, md);

    if(debug) {
      log.debug("Opening output stream " + agent + " : " + new Date());
    }
  }

  private SecretKey getSecretKey()
    throws CertificateException
  {
    return (SecretKey)encryptionService.asymmDecrypt(agent,
      policy.asymmSpec, (SealedObject)dpKey.getObject());
  }

  public void close() throws IOException {
    if(debug) {
      log.debug("Closing output stream " + agent + " : " + new Date());
    }

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
    ObjectOutputStream oos = null;
    try {
      theos.close();
  
      // use this as a marker
      oos = new ObjectOutputStream(out);
      oos.writeInt(bos.size());
      oos.writeInt(genDigest ? 1 : 0);
      oos.flush();
  
      bos.writeTo(out);
      bos.reset();
    }
    catch(IOException iox) {
      publishDataFailure(DataFailureEvent.IO_EXCEPTION, iox.toString());
      throw iox; 
    }
    if (genDigest) {
      // generate digest and sign
      MessageDigest md = ((DigestOutputStream)theos).getMessageDigest();
      String failureIfOccurred = DataFailureEvent.UNKNOWN_FAILURE;  
      try {
        Serializable sobj = new DataProtectionDigestObject(md.digest(), totalBytes);
        if (policy.secureMethod == SecureMethodParam.SIGN
          || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
          failureIfOccurred = DataFailureEvent.SIGNING_FAILURE;
          sobj = encryptionService.sign(agent, policy.signSpec, sobj);
        }
        if (policy.secureMethod == SecureMethodParam.ENCRYPT
          || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
          failureIfOccurred = DataFailureEvent.SECRET_KEY_FAILURE;
          SecretKey skey = getSecretKey();
          failureIfOccurred = DataFailureEvent.ENCRYPT_FAILURE;
          sobj = encryptionService.symmEncrypt(skey, policy.symmSpec, sobj);
        }
        oos = new ObjectOutputStream(out);
        oos.writeObject(sobj);
        oos.flush();
      } 
      catch (GeneralSecurityException gsx) {
        publishDataFailure(failureIfOccurred, gsx.toString());
        throw new IOException("Cannot sign digest: " + gsx.toString());
      }
      catch (IOException iox) {
        publishDataFailure(DataFailureEvent.IO_EXCEPTION, iox.toString());
        throw iox;
      }
    }
  }

  public void write(byte[] b) throws IOException {
    write(b, 0, b.length);
  }

  public void write(int b) throws IOException {
    try {
      theos.write(b);
    }
    catch(IOException iox) {
      publishDataFailure(DataFailureEvent.IO_EXCEPTION, iox.toString());
      throw iox;   
    }
  }

  public void write(byte[] b, int off, int len) throws IOException {
    // update cipher
    totalBytes += len;
    try {
      theos.write(b, off, len);
    }
    catch(IOException iox) {
      publishDataFailure(DataFailureEvent.IO_EXCEPTION, iox.toString());
      throw iox;   
    }
    if (bos.size() > buffersize)
      flushToOutput(false);
  }

  public static int getBufferSize() {
    return buffersize;
  }

  public static void setBufferSize(int size) {
    buffersize = size;
  }
  
  public void addPublisher(EventPublisher publisher) {
    if(eventPublisher == null) {
      eventPublisher = publisher; 
    }
  }
  
   /**
   * publish a data protection failure idmef alert
   */
  private void publishDataFailure(String reason, String data) {
    FailureEvent event = new DataFailureEvent(agent,
                                              agent,
                                              reason,
                                              data);
    if(eventPublisher != null) {
      eventPublisher.publishEvent(event); 
    }
    else {
      if(debug) {
        log.debug("EventPublisher uninitialized, unable to publish event:\n" + event);
      }
    }  
  }
}