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

import org.cougaar.core.mts.SendQueue;
import org.cougaar.core.mts.AttributedMessage;
import org.cougaar.core.mts.ProtectedInputStream;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageAttributes;

import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.security.util.OnTopCipherInputStream;
import org.cougaar.core.security.util.SignatureInputStream;
import org.cougaar.core.security.util.NullOutputStream;

import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.MessageFailureEvent;

class ProtectedMessageInputStream extends ProtectedInputStream {
  private boolean                _eom;
  private boolean                _sign;
  private boolean                _encrypt;
  private boolean                _encryptedSocket;

  private Cipher                 _cipher;
  private String                 _symmSpec;
  private String                 _source;
  private String                 _target;

  private OnTopCipherInputStream _cypherIn;
  private SignatureInputStream   _signature;
  private EventPublisher         _eventPublisher;

  private static LoggingService      _log;
  private static KeyRingService      _keyRing;
  private static CryptoPolicyService _cps;
  private static EncryptionService   _crypto;
  private static SecureRandom        _random = new SecureRandom();

  public ProtectedMessageInputStream(InputStream stream, 
                                     MessageAddress source,
                                     MessageAddress target,
                                     boolean encryptedSocket,
                                     ServiceBroker sb,
                                     EventPublisher publisher) 
    throws GeneralSecurityException, IncorrectProtectionException, 
    IOException {

    super(null);
    init(sb);
    _eventPublisher = publisher;

    if (_log.isDebugEnabled()) {
      _log.debug(source + " -> " + target + 
                 " " + stream);
    }
    _encryptedSocket = encryptedSocket;

    // first get the header:
    byte headerBytes[] = readHeader(stream);
    if (headerBytes.length == 0) {
      throw new MessageDumpedException("Message was dropped");
    }
    ProtectedMessageHeader header = bytesToHeader(headerBytes);
    _source = header.getSenderName();
    _target = header.getReceiverName();
    checkAddresses(source, target);

    _keyRing.checkCertificateTrust(header.getSender());
    _keyRing.checkCertificateTrust(header.getReceiver());

    // check the policy
    boolean ignoreSignature = 
      ignoreSignature(encryptedSocket);
    SecureMethodParam headerPolicy = header.getPolicy();
    boolean goodPolicy = _cps.isReceivePolicyValid(_source, _target,
                                                   headerPolicy,
                                                   encryptedSocket,
                                                   ignoreSignature);

    if (!goodPolicy) {
      if (_log.isDebugEnabled()) {
        _log.debug("Policy mismatch for message from " + _source + 
                   " to " + _target + " for policy " + headerPolicy);
      }
      if (encryptedSocket && 
          headerPolicy.secureMethod == headerPolicy.PLAIN) {
        sendSignatureValid(false); // please send me the signature next time
      }
      throw new IncorrectProtectionException(headerPolicy);
    }

    if (_log.isDebugEnabled()) {
      _log.debug("Using policy: " + headerPolicy + " from " +
                 _source + " to " + _target);
    }

    if (headerPolicy.secureMethod == SecureMethodParam.ENCRYPT ||
        headerPolicy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      decryptStream(header);
    }

    if (headerPolicy.secureMethod == SecureMethodParam.SIGNENCRYPT ||
        headerPolicy.secureMethod == SecureMethodParam.SIGN) {
      unsignStream(header, headerBytes);
    }

    if (_log.isDebugEnabled()) {
      _log.debug("InputStream ready. Reading signed = " + 
                 _sign + ", encrypted = " + _encrypt);
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

  private void publishMessageFailure(String source, String target,
                                     String reason, String data) {
    FailureEvent event = 
      new MessageFailureEvent(source, target, reason, data);
    if (_eventPublisher != null) {
      _eventPublisher.publishEvent(event); 
    } else {
      if (_log.isDebugEnabled()) {
        _log.debug("EventPublisher uninitialized, " +
                   "unable to publish event:\n" + event);
      }
    }  
  }

  /* **********************************************************************
   * ProtectedOutputStream implementation
   */

  public void finishInput(MessageAttributes attributes)
    throws java.io.IOException {
    if (_sign) {
      _log.debug("trying to verify signature");
      try {
        _signature.verifySignature();
      } catch (SignatureException e) {
        _log.debug("Could not verify signature", e);
        publishMessageFailure(_source, _target, "Invalid message signature",
                              e.getMessage());
        throw new IOException(e.getMessage());
      } catch (Exception e) {
        publishMessageFailure(_source, _target, 
                              "Unknown message signature exception",
                              e.getMessage());
        _log.debug("Other exception verifying signature", e);
        throw new IOException(e.getMessage());
      }
      if (_log.isDebugEnabled()) {
        _log.debug("Signature was verified from " + _source +
                   " to " + _target);
      }
      if (_encryptedSocket) {
        _crypto.setReceiveSignatureValid(_source);
        sendSignatureValid(true);
      }
    }
    _eom = true;
    if (_encrypt) {
      _cypherIn.doFinal();
      this.in = null; // so you can't use the Cipher anymore
      _crypto.returnCipher(_symmSpec, _cipher);
      _cipher = null;
    }
  }


  private void sendSignatureValid(boolean isValid) {
    if (_log.isInfoEnabled()) {
      String vmsg;
      if (isValid) {
        vmsg = "stop";
      } else {
        vmsg = "start";
      }
      _log.info("Telling " + _source + " to " + vmsg +
                " signing when talking to " + _target);
    } 
    MessageAddress source = MessageAddress.getMessageAddress(_target);
    MessageAddress target = MessageAddress.getMessageAddress(_source);
    ProtectionLevelMessage pmsg = 
      new ProtectionLevelMessage(source, target, !isValid);
    sendProtectionMessage(pmsg);
  }

  private void sendUseNewCert() {
    if (_log.isInfoEnabled()) {
      _log.info("Telling " + _source + " to start using new certificate " +
                "when talking to " + _target);
    }
    try {
      Hashtable certTable = _keyRing.findCertPairFromNS(_source, _target);
      X509Certificate cert = (X509Certificate) certTable.get(_target);
      MessageAddress source = MessageAddress.getMessageAddress(_target);
      MessageAddress target = MessageAddress.getMessageAddress(_source);
      ProtectionLevelMessage pmsg = 
        new ProtectionLevelMessage(source, target, cert);
      sendProtectionMessage(pmsg);
    } catch (CertificateException e) {
      if (_log.isWarnEnabled()) {
        _log.warn("Can't send a message to " + _source + 
                  " to say that a new certificate is necessary: " +
                  e.getMessage());
      }
    }
  }

  private void sendProtectionMessage(ProtectionLevelMessage pmsg) {
    SendQueue sendQ = MessageProtectionAspectImpl.getSendQueue();
    if (sendQ != null) {
      AttributedMessage msg = 
        new AttributedMessage(pmsg);
//       int contentsId = ~_source.hashCode() ^ _target.hashCode() ^ 
//         pmsg.hashCode();
      msg.setContentsId(_random.nextInt());
      if (pmsg.getMessageType() ==  pmsg.SIGNATURE_NEEDED) {
        msg.setAttribute(MessageProtectionAspectImpl.SIGNATURE_NEEDED,
                         new Boolean(pmsg.isSignatureNeeded()));
      } else {
        msg.setAttribute(MessageProtectionAspectImpl.NEW_CERT,
                         pmsg.getCertificate());
      }
      sendQ.sendMessage(msg);
      _log.debug("Sent message: " + msg);
    } else if (_log.isWarnEnabled()) {
      _log.warn("Could not send message to " + _source + 
                " to use a new certificate. Make sure that " +
                "org.cougaar.core.security.crypto.MessagePr" +
                "otectionAspectImpl is used.");
    }
  }

  private byte[] readHeader(InputStream stream)
    throws IOException {

    this.in = stream;

    DataInputStream din = (stream instanceof DataInputStream) 
      ? (DataInputStream) stream
      : new DataInputStream(stream);

    int bytes = din.readInt();
    byte[] buf = new byte[bytes];
    din.readFully(buf);
    this.in = din;
    return buf;
  }
  
  private ProtectedMessageHeader bytesToHeader(byte[] buf) 
    throws IOException {

    ObjectInputStream ois = 
      new ObjectInputStream(new ByteArrayInputStream(buf));

    try {
      ProtectedMessageHeader header = (ProtectedMessageHeader) 
        ois.readObject();
      if (_log.isDebugEnabled()) {
        _log.debug("ProtectedMessageInputStream header = " + header);
      }
      return header;
    } catch (ClassNotFoundException e) {
      throw new IOException(e.getMessage());
    }
  }
    
  private void checkAddresses(MessageAddress source,
                              MessageAddress target) 
    throws GeneralSecurityException {
    if (!_source.equals(source.toAddress()) ||
        !_target.equals(target.toAddress())) {
      String message = "Break-in attempt: got a message supposedly from " +
        source.toAddress() + " to " + target.toAddress() +
        ", but certificates said " +
        _source + " to " + _target;
      _log.warn(message);
      throw new GeneralSecurityException(message);
    }
  }

  private void decryptStream(ProtectedMessageHeader header)
    throws GeneralSecurityException, 
    IncorrectProtectionException, IOException {

    _encrypt = true;
    // first decrypt the secret key with my private key
    byte[] encKey = header.getEncryptedSymmetricKey();
    SecureMethodParam policy = header.getPolicy();
    SecretKey skey = null;
    try {
      skey = _crypto.decryptSecretKey(policy.asymmSpec,
                                      encKey, policy.symmSpec,
                                      header.getReceiver());
    } catch (GeneralSecurityException e) {
      // can't decrypt using the target's key, try the source key
      // FIXME!! this seems like a problem! You can tell any agent
      // to resend a message as if it had really sent it in the first
      // place
      try {
        skey = _crypto.decryptSecretKey(policy.asymmSpec,
                                        encKey, policy.symmSpec,
                                        header.getSender());
      } catch (GeneralSecurityException e2) {
        sendUseNewCert();
        throw new IncorrectProtectionException(header.getReceiver());
      }
    }

    _symmSpec = policy.symmSpec;
    _cipher = _crypto.getCipher(policy.symmSpec);
    _cipher.init(Cipher.DECRYPT_MODE, skey);
    _cypherIn = new OnTopCipherInputStream(this.in, _cipher);
    this.in = _cypherIn;
  }

  private void unsignStream(ProtectedMessageHeader header, byte[] headerBytes) 
    throws CertificateChainException, NoSuchAlgorithmException,
    CertificateExpiredException, InvalidKeyException, 
    CertificateNotYetValidException, CertificateRevokedException, IOException,
    SignatureException {
    _sign = true;
    X509Certificate senderCert = header.getSender();
    _keyRing.checkCertificateTrust(senderCert);
    PublicKey pub = senderCert.getPublicKey();
    SecureMethodParam policy = header.getPolicy();
    if (_log.isDebugEnabled()) {
      _log.debug("unsigning the message using " + policy.signSpec +
                 " and public key " + pub);
    }
    _signature = new SignatureInputStream(this.in, policy.signSpec, pub);
    this.in = _signature;

    // write the header digest to the stream:
    String digestSpec = policy.signSpec.toLowerCase();
    int withIndex = digestSpec.indexOf("with");
    if (withIndex == -1) {
      withIndex = digestSpec.length();
    }
    digestSpec = policy.signSpec.substring(0,withIndex);
    MessageDigest md = MessageDigest.getInstance(digestSpec);
    DigestOutputStream digest = 
      new DigestOutputStream(new NullOutputStream(), md);
    digest.write(headerBytes);
    digest.close();
    byte digestComputed[] = md.digest();
    byte digestRead[] = new byte[digestComputed.length];
    // now read and compare
    int len = 0;
    while (len < digestRead.length) {
      int bytesRead = read(digestRead, len, digestRead.length - len);
      if (bytesRead >= 0) {
        len += bytesRead;
      } else {
        throw new IOException("Can't read header message digest");
      }
    }

    // now compare digests
    for (int i = 0; i < digestComputed.length; i++) {
      if (digestComputed[i] != digestRead[i]) {
        String message = "The digest of the message header did not compute " +
          "to the same value. Someone has modified the header! " +
          header.getSenderName() + " to " + header.getReceiverName();
        _log.warn(message);
        throw new SignatureException(message);
      }
    }
  }
                     
  public void close() throws IOException {
    if (!_eom) {
      _log.error("can't close");
      throw new IOException("Buffered data cannot be flushed until end of message");
    }
    this.in.close();
  }


  private boolean ignoreSignature(boolean encryptedSocket) {
    if (_log.isDebugEnabled()) {
      _log.debug("Checking ignore of signature -- encrypted: " + 
                 encryptedSocket +
                 ", source = " + _source +
                 ", target = " + _target);
    }

    if (encryptedSocket) {
      return !_crypto.receiveNeedsSignature(_source);
    }
    return false;
  }

}
