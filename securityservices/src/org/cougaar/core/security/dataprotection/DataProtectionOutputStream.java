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
    private DigestOutputStream _digest;
  private Cipher ci;
  private SecretKey skey;

  public static final String strPrefix = "--SIGNATUREBEGIN--";
  public static final String strPostfix = "--SIGNATUREEND--";

  /**
   * buffer size, when reached will flush to output stream
   */
  private static int buffersize = 30000;
  private ByteArrayOutputStream bos = new ByteArrayOutputStream();
//   private OutputStream theos = null;
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

    DataProtectionKeyCollection keyCollection =
      (DataProtectionKeyCollection)pke.getDataProtectionKey();
    dpKey = (DataProtectionKeyImpl)keyCollection.get(0);
    policy = dpKey.getSecureMethod();
    String digestAlg = dpKey.getDigestAlg();

    // encrypt stream
//     theos = bos;

    if (policy.secureMethod == SecureMethodParam.ENCRYPT
      || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      // unprotect key
      String failureIfOccurred = DataFailureEvent.UNKNOWN_FAILURE;
      skey = null;
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
      this.out = new CipherOutputStream(this.out, ci);
    }


    if(debug) {
      log.debug("Opening output stream " + agent + " : " + new Date());
    }
    MessageDigest md = MessageDigest.getInstance(digestAlg);
    _digest = new DigestOutputStream(this.out, md);
    this.out = _digest;

    this.out = new DataOutputStream(this.out);
  }

  private SecretKey getSecretKey()
    throws CertificateException
  {
      /*
      try {
    int i = policy.symmSpec.indexOf("/");
    String a =  (i > 0) 
      ? policy.symmSpec.substring(0,i) 
      : policy.symmSpec;
    SecureRandom random = new SecureRandom();
    KeyGenerator kg = KeyGenerator.getInstance(a);
    kg.init(random);
    return kg.generateKey();
      }
      catch (Exception e) {
	  return null;
      }
      */
      
    return (SecretKey)encryptionService.asymmDecrypt(agent,
      policy.asymmSpec, (SealedObject)dpKey.getObject());
  }

    public void write(int b) throws IOException {
	bos.write(b);
	if (bos.size() > buffersize) {
	    writeChunk();
	}
    }

    public void write(byte b[]) throws IOException {
	bos.write(b);
	if (bos.size() > buffersize) {
	    writeChunk();
	}
    }

    public void write(byte b[], int offset, int len) throws IOException {
	bos.write(b, offset, len);
	if (bos.size() > buffersize) {
	    writeChunk();
	}
    }

    public synchronized void writeChunk() throws IOException {
	((DataOutputStream) this.out).writeInt(bos.size());
	if (log.isDebugEnabled()) {
	    log.debug("Writing " + bos.size() + " to stream");
	}
	
	bos.writeTo(this.out);
	bos = new ByteArrayOutputStream();
    }

    public synchronized void close() throws IOException {
	if (bos.size() > 0) {
	    writeChunk();
	}
	((DataOutputStream) this.out).writeInt(0);
	byte[] digest = _digest.getMessageDigest().digest();
	((DataOutputStream) this.out).writeInt(digest.length);
	this.out.write(digest);
	super.close();
	if (ci != null) {
	    encryptionService.returnCipher(policy.symmSpec, ci);
	    ci = null;
	    this.out = null;
	}
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
