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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.monitoring.event.MessageFailureEvent;
import org.cougaar.core.security.policy.CryptoPolicy;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.ssl.KeyManager;
import org.cougaar.core.security.ssl.KeyRingSSLServerFactory;
import org.cougaar.core.security.util.ErasingMap;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.io.Serializable;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignedObject;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import sun.security.x509.X500Name;

public class CryptoManagerServiceImpl
  implements EncryptionService
{
  private static final MessageFormat MF = new MessageFormat("{0} -");
  private static final int DEFAULT_INIT_BUFFER_SIZE = 200;
  private static final char KEY_LEN_DELIM = '#';
  private static final char PROVIDER_DELIM_START = '{';
  private static final char PROVIDER_DELIM_END   = '}';


  private KeyRingService keyRing;
  private KeyManager clientSSLKeyManager;
  private CertificateCacheService cacheService;
  private ServiceBroker serviceBroker;
  private LoggingService log;
  private Hashtable ciphers = new Hashtable();
  private Map _sendingAgentCerts = new ErasingMap();
  private Map _keyGenerators = new HashMap();

  /** A hashtable that contains encrypted session keys.
   *  The session keys may be used for multiple messages instead of having to generate and encrypt
   *  the secret key every time a message is sent.
   *  The hashtable key is an MessageAddressPair
   *  The hashtable value is a SealedObject (the encrypted session key)
   */
  private Hashtable sessionKeys;

  public CryptoManagerServiceImpl(KeyRingService aKeyRing, ServiceBroker sb) {
    keyRing = aKeyRing;
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    sessionKeys = new Hashtable();
    cacheService = (CertificateCacheService) 
      sb.getService(this, CertificateCacheService.class, null);
    try {
      clientSSLKeyManager = keyRing.getClientSSLKeyManager();
    } catch (IllegalStateException ise) { 
      log.error("No client ssl key manager found - will always sign messages",
                ise);
    }
    if (log.isDebugEnabled()) {
      log.debug("clientSSLKeyManager = " + clientSSLKeyManager);
    }
  }

  private PrivateKey getPrivateKey(String name) 
    throws GeneralSecurityException, IOException {
    return (PrivateKey) getPrivateKeys(name).iterator().next();
  }

  private List getPrivateKeys(final String name) 
    throws GeneralSecurityException, IOException {
    List pkList = (List)
      AccessController.doPrivileged(new PrivilegedAction() {
          public Object run(){
            // relieve messages to naming, for local keys
            // do not need to go to naming
            List nameList = keyRing.getX500NameFromNameMapping(name);
            //List nameList = keyRing.findDNFromNS(name);
            if (log.isDebugEnabled()) {
              log.debug("List of names for " + name + ": " + nameList);
            }
            List keyList = new ArrayList();
            for (int i = 0; i < nameList.size(); i++) {
              X500Name dname = (X500Name)nameList.get(i);
              List pkCerts = keyRing.findPrivateKey(dname);
              if (pkCerts == null) {
                return keyList;
              }
              Iterator iter = pkCerts.iterator();
              while (iter.hasNext()) {
                PrivateKeyCert pkc = (PrivateKeyCert) iter.next();
                keyList.add(pkc.getPrivateKey());
              }
            }
            return keyList;
          }
        });
    if (pkList == null || pkList.size() == 0) {
      String message = "Unable to get private key of " + 
        name + " -- does not exist.";
      if (log.isWarnEnabled()) {
        log.warn(message);
      }
      throw new NoValidKeyException(message);
    }
    return pkList;
  }

  public SignedObject sign(String name,
			   String spec,
			   Serializable obj)
    throws GeneralSecurityException, IOException {
    PrivateKey pk = getPrivateKey(name);
    Signature se;
    // if(spec==null||spec=="")spec=pk.getAlgorithm();

    // Richard Liao
    // private key might not be found, if pending is required
    // the certficates are not approved automatically.
    // when agent is started with signAndEncrypt without
    // obtaining a certificate successfully this will generate
    // null pointer exception

    spec = AlgorithmParam.getSigningAlgorithm(pk.getAlgorithm());
    se=Signature.getInstance(spec);
    return new SignedObject(obj, pk, se);
  }

  public Cipher getCipher(String spec)
    throws NoSuchAlgorithmException, NoSuchPaddingException,
    NoSuchProviderException {
    ArrayList list;
    cipherTry++;
    if (log.isDebugEnabled()) {
      if (cipherTry != 0 && ((cipherTry % 100) == 0)) {
        log.debug("cipher try: " + cipherTry + " hit: " + cipherHit + " return: " + cipherReturn);
      }
    }

    synchronized (this.ciphers) {
      list = (ArrayList) this.ciphers.get(spec);
      if (list == null) {
        list = new ArrayList();
        this.ciphers.put(spec,list);
      }
    }

    synchronized (list) {
      if (!list.isEmpty()) {
        cipherHit++;
        return (Cipher) list.remove(list.size() - 1);
      }
    }
    String alg = specToTransformation(spec);
    String provider = specToProvider(spec);
    if (provider == null) {
      return Cipher.getInstance(alg);
    } else {
      return Cipher.getInstance(alg, provider);
    }
  }

  public static String specToTransformation(String spec) {
    int index = spec.indexOf('/');
    int jndex = spec.indexOf(KEY_LEN_DELIM);
    String alg;
    if (jndex != -1) {
      if (index != -1) {
        alg = spec.substring(0,jndex) + spec.substring(index);
      } else {
        alg = spec.substring(0,jndex);
      }
    } else {
      alg = spec;
    }
    index = alg.indexOf(PROVIDER_DELIM_START);
    if (index != -1) {
      return alg.substring(0, index);
    }
    return alg;
  }

  public int specToKeyLength(String spec) {
    String origSpec = spec;
    int index = spec.indexOf(PROVIDER_DELIM_START);
    if (index != -1) {
      spec = spec.substring(0,index);
    }
    index = spec.indexOf('/');
    if (index != -1) {
      spec = spec.substring(0,index);
    }
    index = spec.indexOf(KEY_LEN_DELIM);
    if (index != -1) {
      try {
        return Integer.parseInt(spec.substring(index+1));
      } catch (NumberFormatException e) {
        log.error("Error getting key length of spec " + origSpec,
                  e);
      }
    }
    return -1;
  }

  public static String specToAlgorithm(String spec) {
    int index = spec.indexOf(PROVIDER_DELIM_START);
    if (index != -1) {
      spec = spec.substring(0, index);
    }
    index = spec.indexOf('/');
    if (index != -1) {
      spec = spec.substring(0,index);
    }
    index = spec.indexOf(KEY_LEN_DELIM);
    if (index != -1) {
      spec = spec.substring(0, index);
    }
    return spec;
  }

  public static String specToProvider(String spec) {
    int index = spec.indexOf(PROVIDER_DELIM_START);
    if (index != -1) {
      int jndex = spec.indexOf(PROVIDER_DELIM_END, index);
      return spec.substring(index + 1, jndex);
    }
    return null;
  }

  /**
   * Creates a secret key from a symmetric key spec.
   * The spec format is similar to the algorithm
   * used in the getInstance with two additions. The
   * transformation (RC4/DES/etc) can be followed by
   * a hyphen and key length. The provider can follow
   * the entire algorithm in parentheses. A complex
   * example is:<p>
   * <tt>AES#192/CBC/WithCTS{BC}</tt>
   * <p>
   * The key length and provider are optional.
   *
   * @param spec The symmetric spec described above
   * @return A new secret key following the given spec
   */
  public SecretKey createSecretKey(String spec) 
    throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyGeneratorEntry kge;
    String origSpec = spec;
    synchronized (_keyGenerators) {
      kge = (KeyGeneratorEntry) _keyGenerators.get(spec);

      if (kge == null) {
        int keyLen;
        String alg;
        String provider;
        KeyGenerator kg;
        SecureRandom random = new SecureRandom();

        int index = spec.indexOf(PROVIDER_DELIM_START);
        if (index != -1) {
          provider = spec.substring(index + 1, 
                                    spec.indexOf(PROVIDER_DELIM_END, index));
          spec = spec.substring(0, index);
        } else {
          provider = null;
        }


        index = spec.indexOf(KEY_LEN_DELIM);
        int jndex = spec.indexOf('/');
        if (index != -1) {
          try {
            if (jndex != -1) {
              keyLen = Integer.parseInt(spec.substring(index + 1, jndex));
            } else {
              keyLen = Integer.parseInt(spec.substring(index + 1));
            }
          } catch (NumberFormatException e) {
            log.error("Error getting key length of spec " + origSpec,
                      e);
            keyLen = -1;
          }
        } else {
          index = jndex;
          keyLen = -1;
        }
        if (index != -1) {
          alg = spec.substring(0, index);
        } else {
          alg = spec;
        }

        if (provider != null) {
          kg = KeyGenerator.getInstance(alg, provider);
        } else {
          kg = KeyGenerator.getInstance(alg);
        }

        if (log.isInfoEnabled()) {
          log.info("key length: " + keyLen);
        }
        if (keyLen != -1) {
          kg.init(keyLen, random);
        } else {
          kg.init(random);
        }
        kge = new KeyGeneratorEntry(kg, keyLen);
        _keyGenerators.put(spec, kge);
      }
    }
    if (log.isInfoEnabled()) {
      log.info("Generating key using KeyGenerator:" + kge.getKeyGenerator()
               + " - spec: " + spec);
    }
    SecretKey sk = null;
    synchronized (kge.getKeyGenerator()) {
      // It looks like some cryptographic providers are thread-safe when
      // generating keys, but not all of them are.
      sk = kge.getKeyGenerator().generateKey();
    }
    /*
    int bits = sk.getEncoded().length * 8;
    int kgKeyLength = kge.getKeyLength();
    while ( (kgKeyLength != -1) && (bits != kgKeyLength)) {
      // The KeyGenerator did not return the expected key length.
      // A really odd problem occured. We need to investigate.
      // Try to reinitialized the key.
      if (log.isWarnEnabled()) {
        log.warn("Key Generator did not return the right key size: "
                 + bits + " instead of " + kgKeyLength
                 + ". Reinitializing KeyGenerator");
      }
      synchronized (kge.getKeyGenerator()) {
        SecureRandom random = new SecureRandom();
        kge.getKeyGenerator().init(kgKeyLength, random);
        sk = kge.getKeyGenerator().generateKey();
      }
      bits = sk.getEncoded().length * 8;
    }
    */
    return sk;
  }

  public void returnCipher(String spec, Cipher cipher) {
    ArrayList list;
    cipherReturn++;
    synchronized (this.ciphers) {
      list = (ArrayList) this.ciphers.get(spec);
    }
    synchronized (list) {
      list.add(cipher);
    }
  }

  public Object verify(String name, String spec, SignedObject obj)
    throws CertificateException {
    return verify(name, spec, obj, false);
  }

  public Object verify(String name, String spec, SignedObject obj, boolean expiredOk)
    throws CertificateException {
    ArrayList signatureIssues = new ArrayList();
    if (obj == null) {
      throw new IllegalArgumentException("Signed object with " + name
					 + " key is null. Unable to verify signature");
    }
    // need to find all certs with the name signed by multiple CAs
    // key not found is ok here, the verifier may not have the private key
    // and it may not have the certificate of a peer
    //List nameList = keyRing.findDNFromNS(name);
    /*
    List nameList =  keyRing.findDNFromNS(name);
    if (nameList == null || nameList.size() == 0) {
      nameList = keyRing.getX500NameFromNameMapping(name);
    }
    */

    List nameList = null;
    int lookupFlags[] = { KeyRingService.LOOKUP_KEYSTORE |
                          KeyRingService.LOOKUP_LDAP,
                          KeyRingService.LOOKUP_KEYSTORE |
                          KeyRingService.LOOKUP_LDAP |
                          KeyRingService.LOOKUP_FORCE_LDAP_REFRESH };

      for (int j = 0; j < lookupFlags.length; j++) {
        if (j == 0) {
          nameList = keyRing.getX500NameFromNameMapping(name);
        }
        else {
          try {
            nameList = keyRing.findDNFromNS(name);
          } catch (IOException iox) {
            continue;
          }
        }

        for (int i = 0; i < nameList.size(); i++) {
          X500Name dname = (X500Name)nameList.get(i);

          List certList = keyRing.findCert(dname, lookupFlags[j], !expiredOk);
          if (certList == null || certList.size() == 0) {
            continue;
          }

          Object o = verify(certList, obj, expiredOk, signatureIssues);
          if (o != null)
	    return o;
        }
      }

    // No suitable certificate was found.
    if (log.isWarnEnabled()) {
      log.warn("Signature verification failed. Agent=" + name);
	//+ " - Tried with " + certList.size() + " certificates");
      for (int i = 0 ; i < signatureIssues.size() ; i++) {
	log.warn((String) signatureIssues.get(i));
      }
    }
    throw new NoValidKeyException("Unable to get certificate of "
                                  + name);
  }

  public Object verify(X509Certificate cert, String spec, SignedObject obj, boolean expiredOk)
    throws CertificateException {
    ArrayList signatureIssues = new ArrayList();
    if (obj == null) {
      throw new IllegalArgumentException("Signed object with " + cert.getSubjectDN().getName()
					 + " key is null. Unable to verify signature");
    }

    List certList = Collections.singletonList(new CertificateStatus(cert, null, null, null, null, null));
    Object o = verify(certList, obj, expiredOk, signatureIssues);
    if (o != null) {
      return o;
    }

    // No suitable certificate was found.
    if (log.isWarnEnabled()) {
      log.warn("Signature verification failed. Agent=" + cert.getSubjectDN().getName());
	//+ " - Tried with " + certList.size() + " certificates");
      for (int i = 0 ; i < signatureIssues.size() ; i++) {
	log.warn((String) signatureIssues.get(i));
      }
    }
    throw new NoValidKeyException("Unable to get certificate of "
                                  + cert.getSubjectDN().getName());
  }

  private Object verify(List certList, SignedObject obj, boolean expiredOk, ArrayList signatureIssues) 
    throws CertificateException {
    Iterator it = certList.iterator();

    while (it.hasNext()) {
      CertificateStatus cs = (CertificateStatus)it.next();
      java.security.cert.Certificate c = cs.getCertificate();
      try {
	// filter out those non valid certificates first
        if (expiredOk) {
          try {
            keyRing.checkCertificateTrust((X509Certificate)c);
          } catch (CertificateException ce) {
	    signatureIssues.add("Certificate trust exception:" + ce
				+ ". Certificate:" + (X509Certificate)c);
            if (!(ce instanceof CertificateExpiredException)) {
              continue;
	    }
            if (log.isDebugEnabled()) {
              log.debug("Certificate has expired." + cs.getCertificateAlias());
	    }
          }
        }

	PublicKey pk = c.getPublicKey();
	Signature ve;
	//if(spec==null||spec=="")spec=pk.getAlgorithm();
	String spec = AlgorithmParam.getSigningAlgorithm(pk.getAlgorithm());
	if (spec == null) {
	  log.warn("Unable to retrieve Algorithm specification from key");
	  signatureIssues.add("Unable to retrieve Algorithm specification from key. Certificate:"
			      + (X509Certificate)c);
	  continue;
	}
	ve=Signature.getInstance(spec);
	if (obj.verify(pk,ve)) {
	  return obj.getObject();
	} else {
	  // That's OK. Maybe there is an old certificate which is not
	  // trusted anymore, but we may have a newer one too.
	  signatureIssues.add("Verification failure. Certificate:" + ((X509Certificate)c).toString());
	  continue;
	}
      } catch (Exception e) {
	// That's OK. Maybe there is an old certificate which is not
	// trusted anymore, but we may have a newer one too.
	signatureIssues.add("Unable to verify signature:" + e + ". Certificate:" + (X509Certificate)c);

	if (log.isInfoEnabled()) {
	  log.info("Unable to verify signature", e);
	}
	continue;
      }
    }
    return null;
  }

  public SealedObject asymmEncrypt(String name, String spec, SecretKey skey,
				   java.security.cert.Certificate cert)
    throws GeneralSecurityException, IOException {
    /*encrypt the secret key with receiver's public key*/

    if (skey == null) {
      throw new IllegalArgumentException("SecretKey is null. Cannot encrypt");
    }
    PublicKey key = cert.getPublicKey();

    if (spec==""||spec==null) {
      spec=key.getAlgorithm();
    }
    if (log.isDebugEnabled()) {
      log.debug("Encrypting for " + name + " using " + spec);
    }
    /*init the cipher*/
    Cipher ci = getCipher(spec);
    try {
      ci.init(Cipher.ENCRYPT_MODE,key);
      SealedObject so = new SealedObject(skey,ci);
      return so;
    }
    finally {
      if (ci != null) {
        returnCipher(spec,ci);
      }
    }
  }

  public byte[] encryptSecretKey(String spec, SecretKey skey,
                                 X509Certificate cert) 
    throws GeneralSecurityException {
    /*encrypt the secret key with receiver's public key*/

    PublicKey key = cert.getPublicKey();

    if (spec==""||spec==null) {
      spec=key.getAlgorithm();
    }
    if (log.isDebugEnabled()) {
      log.debug("Encrypting for " + cert.getSubjectDN() + " using " + spec);
    }
    /*init the cipher*/
    Cipher ci = null;
    try {
      ci = getCipher(spec);
      ci.init(Cipher.ENCRYPT_MODE, key);
      return ci.doFinal(skey.getEncoded());
//       SealedObject so = new SealedObject(obj,ci);
//       return so;
    } finally {
      if (ci != null) {
        returnCipher(spec,ci);
      }
    }
  }

  private PrivateKey getPrivateKey(final X509Certificate cert) 
    throws GeneralSecurityException {
    PrivateKey pk = (PrivateKey) 
      AccessController.doPrivileged(new PrivilegedAction() {
          public Object run(){
            return keyRing.findPrivateKey(cert);
          }
        });
    if (pk == null) {
      String message = "Unable to get private key of " + 
        cert + " -- does not exist.";
      throw new NoValidKeyException(message);
    }
    return pk;
  }

  public SecretKey decryptSecretKey(String spec, byte[] encKey,
                                    String keySpec,
                                    X509Certificate cert)
    throws GeneralSecurityException {
    if (cert == null) {
      throw new IllegalArgumentException("Cannot decrypt secret key: Cert is null");
    }
    Cipher ci = null;
    try {
      PrivateKey key = getPrivateKey(cert);
      ci=getCipher(spec);
      ci.init(Cipher.UNWRAP_MODE, key);
      String alg = specToAlgorithm(keySpec);
      return (SecretKey) ci.unwrap(encKey, alg, Cipher.SECRET_KEY);
    } finally {
      if (ci != null) {
        returnCipher(spec, ci);
      }
    }
  }

  public SecretKey asymmDecrypt(String name,
				String spec,
				SealedObject obj) {
    // get secret keys
    List keyList;
    try {
      keyList = getPrivateKeys(name);
    } catch (Exception e) {
      log.warn("Cannot recover message");
      return null;
    }
    Iterator it = keyList.iterator();
    PrivateKey key = null;
    Cipher ci = null;
    while (it.hasNext()) {
      key = (PrivateKey)it.next();
      if(spec==null||spec=="")
	spec=key.getAlgorithm();
      try {
	ci=getCipher(spec);
        ci.init(Cipher.DECRYPT_MODE, key);
        Object o = obj.getObject(ci);
        return (SecretKey) o;
      } catch (Exception e) {
	// That's OK. Maybe there is an old certificate which is not
	// trusted anymore, but we may have a newer one too.
	if (log.isInfoEnabled()) {
          if (it.hasNext()) {
            log.info("Cannot recover message. " + e +
                     ". Trying with next certificate...");
          } else {
            log.warn("Cannot recover message. No other certificates are available. ",
                     e);
          }
	}
	continue;
      } finally {
        if (ci != null) {
          returnCipher(spec,ci);
        }
      }
    }
    return null;
  }

  public SealedObject symmEncrypt(SecretKey sk,
				  String spec,
				  Serializable obj)
  throws GeneralSecurityException, IOException {
    /*create the cipher and init it with the secret key*/
    Cipher ci;
    ci=getCipher(spec);
    try {
      ci.init(Cipher.ENCRYPT_MODE,sk);
      SealedObject so = new SealedObject(obj,ci);
      return so;
    }
    finally {
      if (ci != null) {
        returnCipher(spec,ci);
      }
    }
  }

  public Object symmDecrypt(SecretKey sk, SealedObject obj, String spec){
    Object o = null;
    if (sk == null) {
      if (log.isErrorEnabled()) {
	      log.error("Secret key not provided!");
      }
      return o;
    }

    Cipher ci = null;
    try{
      ci = getCipher(spec);
      ci.init(Cipher.DECRYPT_MODE, sk);
      o = obj.getObject(ci);
      return o;
    }
    catch(NullPointerException nullexp){
      boolean loop = true;
      if (log.isDebugEnabled()) {
	      log.debug("in symmDecrypt" +nullexp);
      }
      while(loop){
      	try{
      	  Thread.sleep(200);
          ci.init(Cipher.DECRYPT_MODE, sk);
          o = obj.getObject(ci);
      	  if (log.isWarnEnabled()) {
      	    log.warn("Workaround to Cougaar core bug. Succeeded");
      	  }
      	  return o;
      	}
      	catch(NullPointerException null1exp){
      	  if (log.isWarnEnabled()) {
      	    log.warn("Workaround to Cougaar core bug (Context not known). Sleeping 200ms then retrying...");
      	  }
      	  continue;
      	}
      	catch(Exception exp1){
      	  log.info("Unable to decrypt object", exp1);
      	  continue;
      	}
      }
      return null;
    }
    catch(Exception e){
      if (log.isErrorEnabled()) {
	      log.error("Unable to decrypt object", e);
      }
      return null;
    }
    finally {
      if (ci != null) {
        returnCipher(spec,ci);
      }
    }
  }

  public ProtectedObject protectObject(Serializable object,
				       MessageAddress source,
				       MessageAddress target,
				       SecureMethodParam policy)
  throws GeneralSecurityException, IOException {
    ProtectedObject po = null;

    if (object == null) {
      throw new IllegalArgumentException("Object to protect is null");
    }
    if (source == null) {
      throw new IllegalArgumentException("Source not specified");
    }
    if (target == null) {
      throw new IllegalArgumentException("Target not specified");
    }
    if (policy == null) {
      throw new IllegalArgumentException("Policy not specified");
    }

    int method = policy.secureMethod;
    if (log.isDebugEnabled()) {
      log.debug("Protect object " + source.toAddress() + " -> "
		+ target.toAddress() + " with policy: "
		+ method);
    }
    try {
      switch(method) {
      case SecureMethodParam.PLAIN:
      	po = new ProtectedObject(policy, object);
      	break;
      case SecureMethodParam.SIGN:
      	po = sign(object, source, target, policy);
      	break;
      case SecureMethodParam.ENCRYPT:
      	po = encrypt(object, source, target, policy);
      	break;
      case SecureMethodParam.SIGNENCRYPT:
      	po = signAndEncrypt(object, source, target, policy);
      	break;
      default:
	throw new GeneralSecurityException("Invalid policy:" + policy.getSecureMethodToString());
      }
    }
    catch (GeneralSecurityException gse) {
      if (gse instanceof CertificateException) {
        if (log.isDebugEnabled()) {
          log.debug("Unable to protect object: " + source.toAddress()
                   + " -> " + target.toAddress() + " - policy=" + method, gse);
        }
      }
      else {
        if (log.isWarnEnabled()) {
          log.warn("Unable to protect object: " + source.toAddress()
                   + " -> " + target.toAddress() + " - policy=" + method, gse);
        }
      }
      throw gse;
    }
    catch (IOException e) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to protect object: " + source.toAddress()
		 + " -> " + target.toAddress() + " - policy=" + method);
      }
      throw e;
    }
    return po;
  }

  public Object unprotectObject(MessageAddress source,
				MessageAddress target,
				ProtectedObject protectedObject,
				SecureMethodParam policy)
  throws GeneralSecurityException {
    Object theObject = null;
    if (protectedObject == null) {
      throw new IllegalArgumentException("Object to unprotect is null");
    }
    if (source == null) {
      throw new IllegalArgumentException("Source not specified");
    }
    if (target == null) {
      throw new IllegalArgumentException("Target not specified");
    }
    if (policy == null) {
      throw new IllegalArgumentException("Policy not specified");
    }

    // Check the policy.
    if (policy.secureMethod != protectedObject.getSecureMethod().secureMethod) {
      // The object does not comply with the policy
      GeneralSecurityException gse =
        new GeneralSecurityException("Object does not comply with the policy");
      throw gse;
    }

    // Unprotect the message.
    int method = policy.secureMethod;
    if (log.isDebugEnabled()) {
      log.debug("Unprotect object " + source.toAddress() + " -> "
		+ target.toAddress() + "with policy: "
		+ method);
    }
    try {
      switch(method) {
      case SecureMethodParam.PLAIN:
      	theObject = protectedObject.getObject();
      	break;
      case SecureMethodParam.SIGN:
      	theObject = verify(source, target,
      			   (PublicKeyEnvelope)protectedObject,
      			   policy);
      	break;
      case SecureMethodParam.ENCRYPT:
      	theObject = decrypt(source, target,
      			    (PublicKeyEnvelope)protectedObject,
      			    policy);
      	break;
      case SecureMethodParam.SIGNENCRYPT:
      	theObject = decryptAndVerify(source, target,
      				     (PublicKeyEnvelope)protectedObject,
      				     policy);
      	break;
      default:
	      throw new GeneralSecurityException("Invalid policy:" + policy.getSecureMethodToString());
      }
    }
    catch (GeneralSecurityException gse) {
      if (log.isWarnEnabled()) {
      	log.warn("Unable to unprotect object: " + source.toAddress()
      		 + " -> " + target.toAddress() + " - policy=" + method);
      }
      throw gse;
    }
    return theObject;
  }

  private PublicKeyEnvelope sign(Serializable object,
				 MessageAddress source,
				 MessageAddress target,
				 SecureMethodParam policy)
    throws GeneralSecurityException, IOException {
    if (log.isDebugEnabled()) {
      log.debug("Sign object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }
    // Find source certificate
    //X509Certificate sender = keyRing.findFirstAvailableCert(source.toAddress());
    SignedObject signedObject = sign(source.toAddress(), policy.signSpec, object);

    PublicKeyEnvelope pke =
      new PublicKeyEnvelope(null, null, source, target, policy, null, null, signedObject);
    return pke;
  }

  private SessionKeySet getSessionKeySet(MessageAddress source,
					 MessageAddress target,
					 SecureMethodParam policy)
    throws GeneralSecurityException, IOException {
    skeyTry++;
    if (skeyTry != 0 && ((skeyTry % 50) == 0)) {
      log.debug("encrypt key try: " + skeyTry + " hit: " + skeyHit);
    }

    /* Have we already generated a session key for this pair of agents? */
    Hashtable targets;

    synchronized (sessionKeys) {
      targets = (Hashtable) sessionKeys.get(source.toAddress());
      if (targets == null) {
	targets = new Hashtable();
	sessionKeys.put(source.toAddress(), targets);
      }
    }

    synchronized (targets) {
      SessionKeySet so = (SessionKeySet) targets.get(target.toAddress());
      // Find target & receiver certificates
      Hashtable certTable = keyRing.findCertPairFromNS(source.toAddress(), 
						       target.toAddress());
      X509Certificate sender = (X509Certificate)
	certTable.get(source.toAddress());
      X509Certificate receiver = (X509Certificate)
	certTable.get(target.toAddress());
      if (sender == null) {
	String msg = "Cannot create session key. Sender certificate not found: "
	  + source.toAddress();
	if (log.isDebugEnabled()) {
	  log.debug(msg);
	}
	throw new CertificateException(msg);
      }
      if (receiver == null) {
	String msg = "Cannot create session key. Receiver certificate not found: "
	  + target.toAddress();
	if (log.isDebugEnabled()) {
	  log.debug(msg);
	}
	throw new CertificateException(msg);
      }

      if (so == null || !so.receiverCert.equals(receiver) ||
          !so.senderCert.equals(sender)) {
	/*generate the secret key*/
        SecretKey sk = createSecretKey(policy.symmSpec);
	if (log.isDebugEnabled()) {
	  log.debug("Generating new secret key: " + source + " -> " + target);
	}

	// Encrypt session key
	byte[] secretReceiver = encryptSecretKey(policy.asymmSpec, sk, receiver);
	byte[] secretSender = encryptSecretKey(policy.asymmSpec, sk, sender);
	so = new SessionKeySet(sk, secretSender, secretReceiver,
                               sender, receiver);
	targets.put(target.toAddress(), so);
	if (log.isDebugEnabled()) {
	  log.debug("Encrypted secret key " + source + " -> " + target +
		    " of " +
		    ProtectedMessageInputStream.byteArray2String(sk.getEncoded()) +
		    " to " +
		    ProtectedMessageInputStream.byteArray2String(secretReceiver) +
		    " using public key of " + receiver);
	}
      }
      else {
	skeyHit++;
      }
      return so;
    }
  }

  private PublicKeyEnvelope encrypt(Serializable object,
				    MessageAddress source,
				    MessageAddress target,
				    SecureMethodParam policy)
    throws GeneralSecurityException, IOException {
    if (log.isDebugEnabled()) {
      log.debug("Encrypt object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }
    PublicKeyEnvelope pke = null;

    SessionKeySet so = getSessionKeySet(source, target, policy);
    byte[] secretReceiver = so.receiverSecretKey;
    byte[] secretSender = so.senderSecretKey;
    SecretKey sk = so.secretKey;
    SealedObject sealedMsg = symmEncrypt(sk, policy.symmSpec, object);

    pke = new PublicKeyEnvelope(keyRing.buildCertificateChain(so.senderCert),
                                so.receiverCert,
                                source, target, policy, secretSender,
                                secretReceiver, sealedMsg);
    return pke;
  }

  private PublicKeyEnvelope signAndEncrypt(Serializable object,
					   MessageAddress source,
					   MessageAddress target,
					   SecureMethodParam policy)
    throws GeneralSecurityException, IOException {
    if (log.isDebugEnabled()) {
      log.debug("Sign&Encrypt object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }

    PublicKeyEnvelope envelope = null;
    SessionKeySet so = getSessionKeySet(source, target, policy);
    byte[] secretReceiver = so.receiverSecretKey;
    byte[] secretSender = so.senderSecretKey;
    SecretKey sk = so.secretKey;

    if (log.isDebugEnabled()) {
      log.debug("Encrypting " + source + " -> " + target + ": " +
		ProtectedMessageInputStream.byteArray2String(sk.getEncoded()));
    }
    if(log.isDebugEnabled()) {
      log.debug("Signing object with " + source.toAddress() + " key");
    }
    // Sign object
    SignedObject signedObject = sign(source.toAddress(), policy.signSpec, object);

    if(log.isDebugEnabled()) {
      log.debug("Encrypting object");
    }
    // Encrypt object
    SealedObject sealedObject;
    sealedObject = symmEncrypt(sk, policy.symmSpec, signedObject);
    if(log.isDebugEnabled()) {
      log.debug("Looking up source & target certificate");
    }

    envelope =
      new PublicKeyEnvelope(keyRing.buildCertificateChain(so.senderCert),
                            so.receiverCert, source, target, policy,
			    secretSender, secretReceiver, sealedObject);
    if(log.isDebugEnabled()) {
      log.debug("Created secure envelope: " + envelope);
    }

    return envelope;
  }

  int cipherTry = 0;
  int cipherHit = 0;
  int cipherReturn = 0;
  int keyTry = 0;
  int keyHit = 0;
  int skeyTry = 0;
  int skeyHit = 0;

  /** Return the secret key of a protected object.
   * The session key should have been encrypted with both the source
   * and the target.
   */
  private SecretKey getSecretKey(MessageAddress source,
				 MessageAddress target,
				 PublicKeyEnvelope envelope,
				 SecureMethodParam policy)
    throws GeneralSecurityException, IOException {
    SecretKey sk = null;

    keyTry++;
    if (keyTry != 0 && ((keyTry % 50) == 0)) {
      log.debug("decrypt try: " + keyTry + " hit: " + keyHit);
    }

    Hashtable targets;

    synchronized (sessionKeys) {
      targets = (Hashtable) sessionKeys.get(source.toAddress());
      if (targets == null) {
	targets = new Hashtable();
	sessionKeys.put(source.toAddress(), targets);
      }
    }

    synchronized (targets) {
      SessionKeySet so = (SessionKeySet) targets.get(target.toAddress());
      if (so != null) {
	keyHit++;
	if (!Arrays.equals(so.receiverSecretKey,
			   envelope.getEncryptedSymmetricKey()) ||
	    !Arrays.equals(so.senderSecretKey,
			   envelope.getEncryptedSymmetricKeySender())) {
	  so = null; // The key used is actually different - reset it.
	} else {
	  sk = so.secretKey;
	}
      }

      if (sk != null) {
	return sk;
      }

      /* The object was encrypted for a remote agent. However,
       * the remote agent may not be able to process that message, and
       * the source agent wants to get the object back.
       * There could be multiple reasons why the remote agent
       * did not process the object: the infrastructure was
       * not able to send the message, the remote agent did
       * not accept the message, etc.
       */
      if (envelope.getEncryptedSymmetricKey() == null) {
	log.warn("EncryptedSymmetricKey of receiver null");
      }
      X509Certificate sender[] = envelope.getSender();
      X509Certificate receiver = envelope.getReceiver();
/*
      if (sender == null || receiver == null) {
        Hashtable certTable = keyRing.findCertPairFromNS(source.toAddress(), target.toAddress());
	sender = (X509Certificate)certTable.get(source.toAddress());
	receiver = (X509Certificate)certTable.get(target.toAddress());
      }
*/
      if (sender != null && receiver != null) {
        keyRing.checkCertificateTrust(receiver);
        for (int i = sender.length - 1; i >= 0; i--) {
          keyRing.checkCertificateTrust(sender[i]);
          cacheService.addSSLCertificateToCache(sender[i]);
        }
	try {
	  sk = (SecretKey)
	    decryptSecretKey(policy.asymmSpec,
			     envelope.getEncryptedSymmetricKey(),
			     policy.symmSpec,
			     receiver);
	  if (log.isDebugEnabled()){
	    log.debug("Decrypted secret key " + source + " -> " + target +
		      " from " +
		      ProtectedMessageInputStream.byteArray2String(envelope.getEncryptedSymmetricKey()) +
		      " to " + ProtectedMessageInputStream.byteArray2String(sk.getEncoded()) +
		      " using private key of " + receiver);
	  }
	} catch (GeneralSecurityException e) {
	  // Try with the source address
	  if (envelope.getEncryptedSymmetricKeySender() == null) {
	    log.warn("EncryptedSymmetricKey of sender null");
	  }
	  try {
	    sk = (SecretKey)
	      decryptSecretKey(policy.asymmSpec,
			       envelope.getEncryptedSymmetricKeySender(),
			       policy.symmSpec,
			       sender[0]);
	  } catch (GeneralSecurityException e2) {
	    return null;
	  }
	}
      }
      log.debug("decrypted secret key: " + sk);

      if (sk != null) {
// 	byte[] secretReceiver = encryptSecretKey(policy.asymmSpec, sk, receiver);
// 	byte[] secretSender = encryptSecretKey(policy.asymmSpec, sk, sender);
	SessionKeySet sks = new SessionKeySet(sk, envelope.getEncryptedSymmetricKeySender(),
					      envelope.getEncryptedSymmetricKey(),
					      sender[0],  receiver);
	targets.put(target.toAddress(), sks);
      }
    }
    return sk;
  }

  private void clearSecretKey(MessageAddress source,
			      MessageAddress target) {
    Map targets;
    synchronized (sessionKeys) {
      targets = (Hashtable) sessionKeys.get(source.toAddress());
      if (targets == null) {
	return;
      }
    }
    
    synchronized (targets) {
      targets.remove(target.toAddress());
    }
  }

  private Object decryptAndVerify(MessageAddress source,
				  MessageAddress target,
				  PublicKeyEnvelope envelope,
				  SecureMethodParam policy)
    throws GeneralSecurityException {
    if (log.isDebugEnabled()) {
      log.debug("Decrypt&verify object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }

    // Retrieve the secret key, which was encrypted using the public key
    // of the target.
    SignedObject signedObject = null;
    if(log.isDebugEnabled()) {
      log.debug("Retrieving secret key");
    }
    SecretKey sk = null;
    try {
      sk = getSecretKey(source, target, envelope, policy);
      if (log.isDebugEnabled()){
	log.debug("Decrypting " + source + " -> " + target + ": " +
		  ProtectedMessageInputStream.byteArray2String(sk.getEncoded()));
      }
    }
    catch (Exception ex) {
      if (log.isWarnEnabled()) {
	log.warn("DecryptAndVerify: ", ex);
      }
    }
    if (sk == null) {
      if (log.isErrorEnabled()) {
	log.error("DecryptAndVerify: unable to retrieve secret key. Msg:" + source.toAddress()
		  + " -> " + target.toAddress());
      }
      throw new DecryptSecretKeyException("can't get secret key.");
    }

    if(log.isDebugEnabled()) {
      log.debug("Decrypting object");
    }
    // Decrypt the object
    signedObject =
      (SignedObject)symmDecrypt(sk, (SealedObject)envelope.getObject(), 
                                policy.symmSpec);

    if(log.isDebugEnabled()) {
      log.debug("Verifying signature");
    }
    // Verify the signature
    Object o = null;
    try {
      o = verify(envelope.getSender()[0], policy.signSpec, 
                 signedObject, false);
    }
    catch (CertificateException e) {
      if(log.isErrorEnabled()) {
	log.error("Signature verification failed: " + e);
      }
      throw e;
    }
    return o;
  }

  private Object decrypt(MessageAddress source,
			 MessageAddress target,
			 PublicKeyEnvelope envelope,
			 SecureMethodParam policy)
    throws GeneralSecurityException {
    if (log.isDebugEnabled()) {
      log.debug("Decrypt object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }

    // Retrieving the secret key, which was encrypted using the public key
    // of the target.
    SecretKey sk = null;
    try {
      sk = getSecretKey(source, target, envelope, policy);
    }
    catch (Exception ex) {
      if (log.isWarnEnabled()) {
        log.warn("Decrypt: " + ex);
      }
    }
    if (sk == null) {
      if (log.isErrorEnabled()) {
	log.error("Error: unable to retrieve secret key");
      }
      throw new DecryptSecretKeyException("can't get secret key.");
    }
    // Decrypt the object
    Object o =
      symmDecrypt(sk, (SealedObject)envelope.getObject(), policy.symmSpec);
    return o;
  }

  private Object verify(MessageAddress source,
			MessageAddress target,
			PublicKeyEnvelope envelope,
			SecureMethodParam policy)
    throws GeneralSecurityException {
    if (log.isDebugEnabled()) {
      log.debug("Verify object: " + source.toAddress()
			 + " -> " + target.toAddress());
    }
    // Verify the signature
    Object o = null;
    o = verify(source.toAddress(), policy.signSpec,
	       (SignedObject)envelope.getObject());
    return o;
  }

  public ProtectedObject protectObject(Serializable object,
				       MessageAddress source,
				       MessageAddress target,
				       CryptoPolicy cp)
    throws GeneralSecurityException, IOException{
    if (object == null) {
      throw new IllegalArgumentException("Object to protect is null");
    }
    if (source == null) {
      throw new IllegalArgumentException("Source not specified");
    }
    if (target == null) {
      throw new IllegalArgumentException("Target not specified");
    }
    if (cp == null) {
      throw new IllegalArgumentException("Policy not specified");
    }
    String failureIfOccurred = MessageFailureEvent.UNKNOWN_FAILURE;
    try {
      /* assembly SecureMethodParam:
       * as CryptoPolicy can contain multiple entries for each parameter,
       * every meaningful combinations needs to be checked before declare
       * a failure, i.e. throwing IOException
       */
      SecureMethodParam smp = new SecureMethodParam();
      String method = "";
      ProtectedObject po = null;
      Iterator iter = (cp.getSecuMethod(target.toAddress())).iterator();
      while(iter.hasNext()){
        method = (String)iter.next();
        if(method.equalsIgnoreCase("plain")){
          smp.secureMethod = SecureMethodParam.PLAIN;
          po = getProtection(object,source,target,smp,iter.hasNext());
          if(po!=null) return po;
        }else if(method.equalsIgnoreCase("sign")){
          smp.secureMethod = SecureMethodParam.SIGN;
          failureIfOccurred = MessageFailureEvent.SIGNING_FAILURE;
          Iterator iter2 = (cp.getSignSpec(target.toAddress())).iterator();
          while(iter2.hasNext()){
            smp.signSpec = (String)iter2.next();
            po = getProtection(object, source,target,smp,
                        iter.hasNext() && iter2.hasNext());
            if(po!=null) return po;
          }
        }else if(method.equalsIgnoreCase("encrypt")){
          smp.secureMethod = SecureMethodParam.ENCRYPT;
          failureIfOccurred = MessageFailureEvent.ENCRYPT_FAILURE;
          Iterator iter2 = (cp.getSymmSpec(target.toAddress())).iterator();
          while(iter2.hasNext()){
            smp.symmSpec = (String)iter2.next();
            Iterator iter3 = (cp.getAsymmSpec(target.toAddress())).iterator();
            while(iter3.hasNext()){
              smp.asymmSpec = (String)iter3.next();
              po = getProtection(object, source,target,smp,
                iter.hasNext() && iter2.hasNext() && iter3.hasNext());
              if(po!=null) return po;
            }
          }
        }else if(method.equalsIgnoreCase("signAndEncrypt")){
          smp.secureMethod = SecureMethodParam.SIGNENCRYPT;
          failureIfOccurred = MessageFailureEvent.SIGN_AND_ENCRYPT_FAILURE;
          Iterator iter2 = (cp.getSymmSpec(target.toAddress())).iterator();
          while(iter2.hasNext()){
            smp.symmSpec = (String)iter2.next();
            Iterator iter3 = (cp.getAsymmSpec(target.toAddress())).iterator();
            while(iter3.hasNext()){
              smp.asymmSpec = (String)iter3.next();
              Iterator iter4 = (cp.getSignSpec(target.toAddress())).iterator();
              while(iter4.hasNext()){
                smp.signSpec = (String)iter4.next();
                po = getProtection(object, source,target,smp,
                  iter.hasNext() && iter2.hasNext()
                    && iter3.hasNext() && iter4.hasNext());
                if(po!=null) return po;
              }
            }
          }
        } else {
          smp.secureMethod = SecureMethodParam.INVALID;
          if (log.isErrorEnabled()) {
            log.error("outputStream NOK: " + source.toAddress()
               + " -> " + target.toAddress()
               + "invalid secure method.");
          }
          failureIfOccurred = MessageFailureEvent.INVALID_POLICY;
          throw new GeneralSecurityException("invalid secure method.");
        }
      }//while
    }
    catch(GeneralSecurityException gse) {
      String message = failureIfOccurred + " - " + gse.getMessage();
      throw new GeneralSecurityException(message);
    }

    //fall through
    if (log.isErrorEnabled()) {
      log.error("OutputStream NOK: " + source.toAddress()
         + " -> " + target.toAddress()
         + "none of the crypto parameter works: " + cp.toString());
    }
    String message = MessageFailureEvent.INVALID_POLICY + " - failed protecting object.";
    throw new GeneralSecurityException(message);
  }

  public Object unprotectObject(MessageAddress source,
				MessageAddress target,
				ProtectedObject protectedObject,
				CryptoPolicy cp)
    throws GeneralSecurityException, IOException{
    if (protectedObject == null) {
      throw new IllegalArgumentException("Object to unprotect is null");
    }
    if (source == null) {
      throw new IllegalArgumentException("Source not specified");
    }
    if (target == null) {
      throw new IllegalArgumentException("Target not specified");
    }
    if (cp == null) {
      throw new IllegalArgumentException("Policy not specified");
    }
    String failureIfOccurred = MessageFailureEvent.UNKNOWN_FAILURE;

      /* assembly SecureMethodParam:
       * as CryptoPolicy can contain multiple entries for each parameter,
       * every meaningful combinations needs to be checked before declare
       * a failure, i.e. throwing IOException
       */
      SecureMethodParam smp = new SecureMethodParam();
      String method = "";
      Object rawData = null;
      Iterator iter = (cp.getSecuMethod(source.toAddress())).iterator();
      while(iter.hasNext()){
        method = (String)iter.next();
        if(method.equalsIgnoreCase("plain")){
          smp.secureMethod = SecureMethodParam.PLAIN;
          if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
            rawData = getRawData(protectedObject,source,target,smp,iter.hasNext());
            if(rawData!=null) return rawData;
          }
        }else if(method.equalsIgnoreCase("sign")){
          smp.secureMethod = SecureMethodParam.SIGN;
          failureIfOccurred = MessageFailureEvent.VERIFICATION_FAILURE;
          if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
            Iterator iter2 = (cp.getSignSpec(source.toAddress())).iterator();
            while(iter2.hasNext()){
              smp.signSpec = (String)iter2.next();
              rawData = getRawData(protectedObject, source,target,smp,
                          iter.hasNext() && iter2.hasNext());
              if(rawData!=null) return rawData;
            }
          }
        }else if(method.equalsIgnoreCase("encrypt")){
          smp.secureMethod = SecureMethodParam.ENCRYPT;
          failureIfOccurred = MessageFailureEvent.DECRYPT_FAILURE;
          if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
            Iterator iter2 = (cp.getSymmSpec(source.toAddress())).iterator();
            while(iter2.hasNext()){
              smp.symmSpec = (String)iter2.next();
              Iterator iter3 = (cp.getAsymmSpec(source.toAddress())).iterator();
              while(iter3.hasNext()){
                smp.asymmSpec = (String)iter3.next();
                rawData = getRawData(protectedObject, source,target,smp,
                  iter.hasNext() && iter2.hasNext() && iter3.hasNext());
                if(rawData!=null) return rawData;
              }
            }
          }
        }else if(method.equalsIgnoreCase("signAndEncrypt")){
          smp.secureMethod = SecureMethodParam.SIGNENCRYPT;
          failureIfOccurred = MessageFailureEvent.DECRYPT_AND_VERIFY_FAILURE;
          if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
            Iterator iter2 = (cp.getSymmSpec(source.toAddress())).iterator();
            while(iter2.hasNext()){
              smp.symmSpec = (String)iter2.next();
              Iterator iter3 = (cp.getAsymmSpec(source.toAddress())).iterator();
              while(iter3.hasNext()){
                smp.asymmSpec = (String)iter3.next();
                Iterator iter4 = (cp.getSignSpec(source.toAddress())).iterator();
                while(iter4.hasNext()){
                  smp.signSpec = (String)iter4.next();
                  rawData = getRawData(protectedObject, source,target,smp,
                    iter.hasNext() && iter2.hasNext()
                      && iter3.hasNext() && iter4.hasNext());
                  if(rawData!=null) return rawData;
                }
              }
            }
          }
        }else{
          smp.secureMethod = SecureMethodParam.INVALID;
          if (log.isErrorEnabled()) {
            log.error("readInputStream NOK: " + source.toAddress()
               + " -> " + target.toAddress()
               + "invalid secure method.");
          }
          failureIfOccurred = MessageFailureEvent.INVALID_POLICY;
          throw new GeneralSecurityException("invalid secure method.");
        }
      }//while

    //fall through
    if (log.isErrorEnabled()) {
      log.error("readInputStream NOK: " + source.toAddress()
         + " -> " + target.toAddress()
         + "none of the crypto parameter works: " + cp.toString());
    }
    String message = MessageFailureEvent.INVALID_POLICY + " - failed unprotecting object.";
    throw new GeneralSecurityException(message);
  }//unprotectObj

  private Object getRawData(ProtectedObject obj,
				       MessageAddress source,
				       MessageAddress target,
              SecureMethodParam policy, boolean goOn)
              throws GeneralSecurityException, IOException
  {
    try {
      return unprotectObject(source,
               target,
               obj, policy);
    }
    catch (GeneralSecurityException gse) {
      if(goOn) return null;
      if (log.isWarnEnabled()) {
        log.warn("readInputStream NOK: " + source.toAddress()
           + " -> " + target.toAddress()
           + gse);
      }
      throw gse;
    }
  }//getRawData

  private ProtectedObject getProtection(Serializable obj,
					MessageAddress source,
					MessageAddress target,
					SecureMethodParam policy,
					boolean goOn)
    throws GeneralSecurityException, IOException
  {
    try {
      return protectObject(obj, source, target, policy);
    }
    catch (GeneralSecurityException gse) {
      if(goOn) {
	return null;
      }
      // if cannot find certificate, only put debug message
      // this happens frequently before certificate is obtained
      // at system startup time
      if (gse instanceof CertificateException) {
        if (log.isDebugEnabled()) {
          log.debug("put OutputStream NOK: " + source.toAddress()
                   + " -> " + target.toAddress()
                   + gse);
        }
      }
      else {
        if (log.isWarnEnabled()) {
          log.warn("put OutputStream NOK: " + source.toAddress()
                   + " -> " + target.toAddress()
                   + gse);
        }
      }
      throw gse;
    }
  }//getProtection

  private class SessionKeySet {
    public SessionKeySet(SecretKey sk,
			 byte[] eskSender, byte[] eskReceiver,
                         X509Certificate sndCert, X509Certificate rcvCert) {
      secretKey = sk;
      senderSecretKey = eskSender;
      receiverSecretKey = eskReceiver;
      senderCert = sndCert;
      receiverCert = rcvCert;
    }

    /**
     * The unprotected SecretKey
     */
    public SecretKey secretKey;
    /**
     * The SecretKey protected with the public key of the sender
     */
    public byte[] senderSecretKey;
    /**
     * The SecretKey protected with the public key of the receiver
     */
    public byte[] receiverSecretKey;
    /**
     * The sender's X509Certificate containing the public key used to protect the SecretKey
     */
    public X509Certificate senderCert;
    /**
     * The receiver's X509Certificate containing the public key used to protect the SecretKey
     */
    public X509Certificate receiverCert;
  }

  private static void removeEncrypt(SecureMethodParam policy) {
    if (policy.secureMethod == SecureMethodParam.ENCRYPT) {
      policy.secureMethod = SecureMethodParam.PLAIN;
    } else if (policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      policy.secureMethod = SecureMethodParam.SIGN;
    }
  }

  private static void removeSign(SecureMethodParam policy) {
    if (policy.secureMethod == SecureMethodParam.SIGN) {
      policy.secureMethod = SecureMethodParam.PLAIN;
    } else if (policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      policy.secureMethod = SecureMethodParam.ENCRYPT;
    }
  }

  private synchronized boolean 
    certOk(String source, String nodePrincipal, String target) 
    throws GeneralSecurityException 
  {
    ConnectionInfo ci = new ConnectionInfo(source, nodePrincipal, target);
    X509Certificate cert = (X509Certificate) _sendingAgentCerts.get(ci);
    if (cert != null) {
      try {
        keyRing.checkCertificateTrust(cert);
        return true;
      } catch (GeneralSecurityException e) {
        _sendingAgentCerts.remove(ci);
        throw e;
      }
    }
    return false;
  }

  public boolean receiveNeedsSignature(String source) 
    throws GeneralSecurityException {
    String strP = getRemotePrincipal();
    if (strP != null) {
      boolean invalid = !certOk(source, strP, null);
      if (log.isDebugEnabled()) {
        log.debug("receiveNeedsSignature(" + source + ") " +
                  strP + " -> " + invalid);
      }
      return invalid;
    } else if (log.isDebugEnabled()) {
      log.debug("Principal = null so we must require a signature");
    }
    if (log.isDebugEnabled()) {
      log.debug("receiveNeedsSignature(" + source + ") not SSL");
    }
    return true;
  }

  public boolean sendNeedsSignature(String source, String target) 
    throws GeneralSecurityException {
    X509Certificate [] certs = clientSSLKeyManager.getCertificateChain(null);
    if (certs == null) {
      throw new GeneralSecurityException("No cert for my node??");
    }
    String nodePrincipal = certs[0].getSubjectDN().getName();
    boolean needsSig = !certOk(source, nodePrincipal, target);
    if (log.isDebugEnabled()) {
      log.debug("From " + source + " to " + target + ": need signature? " +
                needsSig);
      log.debug("my node principal = " + nodePrincipal);
    }
    return needsSig;
    // the following will imply that the sender always signs.  We needed it 
    // for a little bit when we had problems with this code.
    // return true;
  }

  public synchronized void setSendNeedsSignature(String source, 
                                                 String nodePrincipal,
                                                 String target)
  {
    ConnectionInfo ci = new ConnectionInfo(source, nodePrincipal, target);
    _sendingAgentCerts.remove(ci);
  }

  public synchronized void removeSendNeedsSignature(String source, 
                                                    String nodePrincipal,
                                                    String target, 
                                                    X509Certificate cert) 
  {
    ConnectionInfo ci = new ConnectionInfo(source, nodePrincipal, target);
    _sendingAgentCerts.put(ci, cert);
  }

  public String getRemotePrincipal()
  {
    Principal p = KeyRingSSLServerFactory.getPrincipal();
    if (p != null) {
      if (log.isDebugEnabled()) {
        log.debug("remote principal = " + p.getName());
      }
      return p.getName();
    } else { return null; }
  }

  public synchronized void setReceiveSignatureValid(String source, 
                                                    X509Certificate cert) 
  {
    String strP = getRemotePrincipal();
    if (strP != null) {
      ConnectionInfo ci = new ConnectionInfo(source, strP);
      synchronized (_sendingAgentCerts) {
        if (log.isDebugEnabled()) {
          log.debug("setReceiveSignatureValid(" + source + ") adding to " +
                    strP);
        }
        _sendingAgentCerts.put(ci, cert);
      }
    } else {
      if (log.isDebugEnabled()) {
        log.debug("setReceiveSignatureValid(" + source + ") not SSL");
      }
    }
  }

  private class KeyGeneratorEntry {
    private KeyGenerator _kg;
    private int _keyLength;
    public KeyGeneratorEntry(KeyGenerator kg, int keyLength) {
      _kg = kg;
      _keyLength = keyLength;
    }
    public KeyGenerator getKeyGenerator() {
      return _kg;
    }
    public int getKeyLength() {
      return _keyLength;
    }
  }

  /*
   * This is a private class representing certain critical information about
   * a connection.  This information will get associated with a known 
   * certificate for the source by the Map, clientSSLKeyManager.
   *
   * I am using a target of null to represent any agent on my node (e.g. 
   * I am receiving a message in a stream for one of my agents.
   */
  private class ConnectionInfo
  {
    private String _source;
    private String _sourceNodePrincipal;
    private String _target;

    public ConnectionInfo(String source, 
                          String sourceNodePrincipal)
    {
      _source              = source;
      _sourceNodePrincipal = sourceNodePrincipal;
      _target              = null;
    }


    public ConnectionInfo(String source, 
                          String sourceNodePrincipal,
                          String target)
    {
      _source              = source;
      _sourceNodePrincipal = sourceNodePrincipal;
      _target              = target;
    }

    public boolean equals(Object o)
    {
      if (o instanceof ConnectionInfo) {
        ConnectionInfo ci = (ConnectionInfo) o;
        return 
          _source.equals(ci._source) &&
          _sourceNodePrincipal.equals(ci._sourceNodePrincipal) &&
          (_target == null ? ci._target == null : _target.equals(ci._target));
      } else { return false; }
    }

    public int hashCode()
    {
      return
        _source.hashCode() + _sourceNodePrincipal.hashCode() +
        (_target == null ? 42 : _target.hashCode());
    }

    public String toString()
    {
      return 
        _source + "/" + _sourceNodePrincipal + " -> "
        + (_target == null ? "me" : _target);
    }
  }
}
