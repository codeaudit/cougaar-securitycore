/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
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
 */

package org.cougaar.core.security.crypto;

import java.io.*;
import java.security.*;
import java.util.*;
import java.security.cert.*;
import javax.crypto.*;
import sun.security.x509.*;

import org.cougaar.core.security.util.SignatureOutputStream;
import org.cougaar.core.security.util.OnTopCipherOutputStream;
import org.cougaar.core.security.util.DumpOutputStream;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.util.NullOutputStream;

import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.ProtectedOutputStream;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;


class ProtectedMessageOutputStream extends ProtectedOutputStream {
  private boolean               _eom = false;
  private boolean               _sign;
  private boolean               _encrypt;

  private String                _source;
  private String                _target;
  private X509Certificate       _sourceCert;
  private X509Certificate       _targetCert;

  private Cipher                _cipher;
  private String                _symmSpec;

  private SignatureOutputStream   _signature;
  private OnTopCipherOutputStream _cipherOut;

  private static LoggingService      _log;
  private static KeyRingService      _keyRing;
  private static CryptoPolicyService _cps;
  private static EncryptionService   _crypto;

  private static int        _fileno = 10000;
  private static final long RANDOM = (new Random()).nextLong();

  public final static String DUMP_PROPERTY =
    "org.cougaar.core.security.crypto.dumpMessages";
  /** Set to true to dump messages to a file (for debug purposes) */
  private static final boolean DUMP_MESSAGES = 
    Boolean.getBoolean(DUMP_PROPERTY);

    private static final HashMap _certCache = new HashMap();

  public ProtectedMessageOutputStream(OutputStream stream,
                                      MessageAddress source,
                                      MessageAddress target,
                                      boolean encryptedSocket,
                                      ServiceBroker sb) 
    throws GeneralSecurityException, IOException {
    super(stream);
    init(sb);

    if (_log.isDebugEnabled()) {
      _log.debug("Sending Message: " + source + " -> " + target);
    }

    _source = source.toAddress();
    _target = target.toAddress();

    SecureMethodParam policy = 
      _cps.getSendPolicy(_source, _target);

    // secret key encrypted by sender or receiver's certificate
    byte[] senderSecret   = null;
    byte[] receiverSecret = null;

    getCertificates(policy);

    SecretKey secret = null;
    if (_log.isDebugEnabled()) {
      _log.debug("Policy = " + policy);
    }
    if (policy == null) {
      dropMessage();
      throw new IOException("This message was denied by policy. " +
                            "There are no possible encryption algorithms " +
                            "to send it.");
    }
    policy = modifyPolicy(policy, encryptedSocket);

    if (_log.isDebugEnabled()) {
      _log.debug("Modified policy = " + policy);
    }

    if (policy.secureMethod == policy.ENCRYPT ||
        policy.secureMethod == policy.SIGNENCRYPT) {
      _encrypt = true;
      // first encrypt the secret key with the target's public key
      secret = _crypto.createSecretKey(policy.symmSpec);
      try {
        senderSecret = 
          _crypto.encryptSecretKey(policy.asymmSpec, secret, _sourceCert);
        receiverSecret = 
          _crypto.encryptSecretKey(policy.asymmSpec, secret, _targetCert);
      } catch (GeneralSecurityException e) {
        _log.error("Could not encrypt secret key. This message will not " +
                  "go out properly! -- we'll retry later", e);
        throw new IOException(e.getMessage());
      }
    }

    ProtectedMessageHeader header = 
      new ProtectedMessageHeader(_keyRing.buildCertificateChain(_sourceCert),
                                 _targetCert,
                                 policy, receiverSecret, senderSecret);
    if (_log.isDebugEnabled()) {
      _log.debug("Sending " + header);
    }
    ByteArrayOutputStream headerBytes = writeHeader(header);

    if (_encrypt) {
      _symmSpec = policy.symmSpec;
      _cipher = _crypto.getCipher(policy.symmSpec);
      _cipher.init(Cipher.ENCRYPT_MODE, secret);
      _cipherOut = new OnTopCipherOutputStream(this.out, _cipher);
      this.out = _cipherOut;
    }
    if (policy.secureMethod == policy.SIGNENCRYPT ||
        policy.secureMethod == policy.SIGN) {
      _sign = true;
      PrivateKey priv = getPrivateKey(_sourceCert);
      _signature =  new SignatureOutputStream(this.out, policy.signSpec, 
                                              priv);
      this.out = _signature;
      MessageDigest md = getMessageDigest(policy.signSpec);
      DigestOutputStream dout = 
        new DigestOutputStream(new NullOutputStream(), md);
      headerBytes.writeTo(dout);
      dout.close();
      write(md.digest());
    }
    if (DUMP_MESSAGES) {
      String filename = getDumpFilename();
      if (_log.isDebugEnabled()) {
        _log.debug("Dumping message content to file " + filename);
      }
      this.out = new DumpOutputStream(this.out, filename);
    }
    if (_log.isDebugEnabled()) {
      _log.debug("Stream from " + source + " to " + target + " ready!");
    }
  }

  /**
   * Initialize all commonly used variables. Minimize the number of
   * calls to the ServiceBroker by using static member variables.
   * Since this class is only used within the aspect, there is no
   * need to worry about differences in agents. All these classes
   * should be reentrant.
   */
  private void init(ServiceBroker sb) {
    if (_log == null) {
      _log = (LoggingService) sb.getService(this, LoggingService.class, null);
      _keyRing = (KeyRingService) 
        sb.getService(this, KeyRingService.class, null);
      _crypto = (EncryptionService)
        sb.getService(this, EncryptionService.class, null);
      _cps = (CryptoPolicyService)
        sb.getService(this, CryptoPolicyService.class, null);
    }
  }

    public static void clearCertCache(String source, String target) {
	synchronized (_certCache) {
	    _certCache.remove(source + ':' + target);
	}
    }

  private void getCertificates(SecureMethodParam policy) 
    throws NoKeyAvailableException, CertificateException, IOException,
    NoSuchAlgorithmException {

    CertEntry certEntry;

    if (policy.secureMethod == policy.PLAIN) {
      return; // don't need any certificates for plain text communication
    }

    synchronized (_certCache) {
      String name = _source + ':' + _target;
      certEntry = (CertEntry) _certCache.get(name);
      if (certEntry == null) {
        certEntry = new CertEntry();
        _certCache.put(name, certEntry);
      }
    }

    synchronized (certEntry) {
      if (certEntry.source == null || certEntry.target == null) {
        Hashtable certs = _keyRing.findCertPairFromNS(_source, _target);
        if (certs != null) {
          certEntry.source = (X509Certificate) certs.get(_source);
          certEntry.target = (X509Certificate) certs.get(_target);
        }
      }
      _targetCert = certEntry.target;
      _sourceCert = certEntry.source;
    }

    if (_sourceCert == null || _targetCert == null) {
      // send a message to receiver that this message is bad:
      if (_sourceCert == null && _log.isDebugEnabled()) {
        _log.debug("Could not find sender certificate for " + _source);
      }
      if (_targetCert == null && _log.isDebugEnabled()) {
        _log.debug("Could not find target certificate for " + _target);
      }
      dropMessage();
      throw new NoKeyAvailableException("No valid key pair found for the " +
                                        "2 message address " + 
                                        _source + " -> " + _target);
    }
  }

  private void dropMessage() throws IOException {
    DataOutputStream dout = new DataOutputStream(this.out);
    dout.writeInt(0); // tell receiver there is no header
    dout.flush();
  }

  public void close() throws IOException {
    if (!_eom) {
      throw new IOException("Buffered data cannot be flushed until end of message");
    }
    super.close();
  }

//   public void write(int b) throws IOException {
//     try {
//       super.write(b);
//     } catch (IOException e) {
//       _log.debug("caught exception when writing", e);
//       throw e;
//     }
//   }

  /* **********************************************************************
   * ProtectedOutputStream implementation
   */

  public void finishOutput(MessageAttributes attributes)
    throws java.io.IOException {
    if (DUMP_MESSAGES) {
      ((DumpOutputStream) out).stopDumping();
    }
    if (_sign) {
      _signature.writeSignature();
    }
    _eom = true;
    if (_encrypt) {
      _cipherOut.doFinal();
      this.flush();
      this.out = null; // so we can't use the cipher anymore
      _crypto.returnCipher(_symmSpec, _cipher);
      _cipher = null;
    }
    if (_log.isDebugEnabled()) {
      _log.debug("finishOutputStream from " + _source + " to " + _target);
    }
  }

  private static SecureMethodParam copyPolicy(SecureMethodParam policy) {
    SecureMethodParam newPolicy = new SecureMethodParam();
    newPolicy.secureMethod = policy.secureMethod;
    newPolicy.symmSpec = policy.symmSpec;
    newPolicy.asymmSpec = policy.asymmSpec;
    newPolicy.signSpec = policy.signSpec;
    return newPolicy;
  }

  private static void removeEncrypt(SecureMethodParam policy) {
    if (policy.secureMethod == policy.ENCRYPT) {
      policy.secureMethod = policy.PLAIN;
    } else if (policy.secureMethod == policy.SIGNENCRYPT) {
      policy.secureMethod = policy.SIGN;
    }
  }

  private static void removeSign(SecureMethodParam policy) {
    if (policy.secureMethod == policy.SIGN) {
      policy.secureMethod = policy.PLAIN;
    } else if (policy.secureMethod == policy.SIGNENCRYPT) {
      policy.secureMethod = policy.ENCRYPT;
    }
  }

  private SecureMethodParam modifyPolicy(SecureMethodParam policy,
                                         boolean encryptedSocket) {
    policy = copyPolicy(policy);

    if (encryptedSocket) {
      removeEncrypt(policy); // no need for double-encryption
    }

    if (policy.secureMethod == policy.SIGN && encryptedSocket && 
        !_crypto.sendNeedsSignature(_source, _target)) {
      policy.secureMethod = policy.PLAIN;
    }

    return policy;
  }

  private ByteArrayOutputStream writeHeader(ProtectedMessageHeader header) 
    throws IOException {
    ByteArrayOutputStream lenOut = new ByteArrayOutputStream();
    DataOutputStream dout = new DataOutputStream(lenOut);
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    ObjectOutputStream oos = 
      new ObjectOutputStream(bout);
    oos.writeObject(header);
    oos.close();
    dout.writeInt(bout.size());
    dout.close();
    lenOut.writeTo(this.out);
    bout.writeTo(this.out);
    if (_log.isDebugEnabled()) {
      _log.debug("wrote header of length: " + bout.size() + 
                 " in message from " + _source + " to " + _target);
    }
    return bout;
  }

  private PrivateKey getPrivateKey(final X509Certificate cert) 
    throws GeneralSecurityException {
    PrivateKey pk = (PrivateKey) 
      AccessController.doPrivileged(new PrivilegedAction() {
          public Object run(){
            return _keyRing.findPrivateKey(cert);
          }
        });
    if (pk == null) {
      String message = "Unable to get private key of " + 
        cert + " -- does not exist.";
      throw new NoValidKeyException(message);
    }
    return pk;
  }

  private static synchronized String getDumpFilename() {
    return "msgDump-" + RANDOM + "-" + _fileno++ + ".dmp";
  }

  public static MessageDigest getMessageDigest(String signatureSpec) 
    throws NoSuchAlgorithmException {
    String digestSpec = signatureSpec.toLowerCase();
    int withIndex = digestSpec.indexOf("with");
    if (withIndex == -1) {
      withIndex = digestSpec.length();
    }
    digestSpec = signatureSpec.substring(0,withIndex);
    return MessageDigest.getInstance(digestSpec);
  }

  private static class CertEntry {
    public X509Certificate source;
    public X509Certificate target;
  }
}
