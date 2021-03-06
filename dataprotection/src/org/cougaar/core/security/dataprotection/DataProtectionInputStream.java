/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.dataprotection;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.monitoring.event.DataFailureEvent;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.publisher.SecurityEventPublisher;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.crypto.SignatureInputStream;
import org.cougaar.core.service.DataProtectionKeyEnvelope;
import org.cougaar.core.service.LoggingService;

public class DataProtectionInputStream extends FilterInputStream {
  private LoggingService log;
  private ServiceBroker serviceBroker;
  private EncryptionService encryptionService;

  private DataProtectionKeyImpl dpKey;
  private static String agent;

  private Cipher ci = null;
  private SecureMethodParam policy = null;

  private SecretKey skey = null;

  private SignatureInputStream _sigIn = null;
  private ChunkInputStream _chunkIn = null;

  private boolean debug = false;

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
    if(log != null) {
      debug = log.isDebugEnabled();
    }

    DataProtectionInputStream.agent = agent;
    DataProtectionKeyCollection keyCollection =
      (DataProtectionKeyCollection)pke.getDataProtectionKey();
    dpKey = (DataProtectionKeyImpl)keyCollection.get(0);
    policy = dpKey.getSecureMethod();

    skey = getSecretKey();
    if (skey == null) {
      publishDataFailure(DataFailureEvent.SECRET_KEY_FAILURE,
			 "Cannot get data protection key");
      throw new GeneralSecurityException("Cannot get data protection key");
    }

    if (policy.secureMethod == SecureMethodParam.ENCRYPT
        || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      try {
        ci=encryptionService.getCipher(policy.symmSpec);
      } catch(GeneralSecurityException gsx) {
        publishDataFailure(DataFailureEvent.INVALID_POLICY, gsx.toString());
        throw gsx;
      }
      ci.init(Cipher.DECRYPT_MODE,skey);
      this.in = new CipherInputStream(this.in, ci);
    }

    _chunkIn = new ChunkInputStream(this.in);
    this.in = _chunkIn;

    if (policy.secureMethod == SecureMethodParam.SIGN ||
        policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      String sigAlg = policy.signSpec;
      PublicKey pkey = dpKey.getCertificateChain()[0].getPublicKey();
      _sigIn = new SignatureInputStream(this.in, sigAlg, pkey);
      this.in = _sigIn;
    }

    if(debug) {
      log.debug("Opening inputStream: " + agent + " : " + new Date());
    }
  }

  public synchronized void close() throws IOException {
    if (log.isDebugEnabled()) {
      log.debug("Closing...");
    }
    // read until the end of file
    if (this.in == null) {
      if (log.isDebugEnabled()) {
        log.debug("Closed already");
      }
      return;
    }

    if (_sigIn != null) {
      // read to the end
      while (read() != -1);
      _chunkIn.resetEnd();
      try {
        _sigIn.verifySignature();
      } catch (SignatureException e) {
        log.debug("Digest does not match");
        publishDataFailure(DataFailureEvent.VERIFY_DIGEST_FAILURE,
                           e.toString());
        throw new IOException("Digest does not match");
      }
    }

    super.close();
    if (ci != null) {
      encryptionService.returnCipher(policy.symmSpec, ci);
      ci = null;
    }
    this.in = null;
    log.debug("Closed");

    DataProtectionStatus.addInputStatus(
      agent, DataProtectionStatus.INPUT_COMPLETE);
  }

  private SecretKey getSecretKey()
    throws GeneralSecurityException
  {
    return encryptionService.decryptSecretKey(
      policy.asymmSpec, (byte[])dpKey.getObject(),
      policy.symmSpec, dpKey.getCertificateChain()[0]);
  }

  /**
   * publish a data protection failure idmef alert
   */
  private static void publishDataFailure(String reason, String data) {
    FailureEvent event = new DataFailureEvent(agent,
                                              agent,
                                              reason,
                                              data);
    SecurityEventPublisher.publishEvent(event);
  }

  private static class ChunkInputStream extends FilterInputStream {
    boolean _eof = false;
    private boolean _isReset = false;

    private byte[] _byteBuf = new byte[40000];
    private ByteArrayInputStream _buf =
      new ByteArrayInputStream(_byteBuf, 0, 0);

    public ChunkInputStream(InputStream is) {
      super(new DataInputStream(is));
    }

    public int read() throws IOException {
      if (_isReset) { return super.read(); }
      if (_eof) {
        return -1;
      }
      refillBuf();
      return _buf.read();
    }

    public int read(byte[] b, int off, int len) throws IOException {
      if (_isReset) {
        return super.read(b, off, len);
      }
      if (_eof) {
        return -1;
      }
      refillBuf();
      return _buf.read(b, off, len);
    }

    public int read(byte[] b) throws IOException {
      return read(b, 0, b.length);
    }

    public synchronized void refillBuf() throws IOException {
        try {
      if (_buf.available() == 0 && !_eof) {
        int len = ((DataInputStream) this.in).readInt();
        if (len == 0) {
          _eof = true;
          return;
        }
        if (_byteBuf.length < len) {
          _byteBuf = new byte[len];
        }

        ((DataInputStream)this.in).readFully(_byteBuf, 0, len);
        _buf = new ByteArrayInputStream(_byteBuf, 0, len);
      }
        } catch (Exception iox) {
          publishDataFailure(DataFailureEvent.VERIFY_DIGEST_FAILURE, 
            iox.toString());
          throw new IOException(iox.toString());
        }
    }

    public synchronized void resetEnd() throws IOException {
      _isReset = true;
    }

    public int available() throws IOException {
      return _buf.available();
    }

    public boolean markSupported() {
      return false;
    }

  }
}
