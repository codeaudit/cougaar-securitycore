/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 *
 * Created on September 12, 2001, 10:55 AM
 */

package com.nai.security.crypto;

import org.cougaar.util.ConfigFinder;

import java.io.*;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.Vector;
import java.util.Properties;
import java.util.Collection;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Principal;
import java.security.cert.*;
import java.security.KeyPair;

import com.nai.security.certauthority.*;

import sun.security.pkcs.*;

/** A common holder for Security keystore information and functionality
 **/

final public class KeyRing implements Runnable {
  // keystore stores private keys and well-know public keys
  private static String ksPass;
  private static String ksPath;
  private static KeyStore keystore = null;

  // CA keystore
  private static String caksPass;
  private static String caksPath;
  private static KeyStore cakeystore = null;

  private static String provider_url=null;
  private static CertificateFinder certificatefinder=null;
  private static long sleep_time=2000l; 
  private static boolean debug = false;
  private static HashMap m = new HashMap();

  private static Object initLock = new Object();
  private static HashMap privateKeys = new HashMap(89);
  private static HashMap certs = new HashMap(89);

  static {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    String installpath = System.getProperty("org.cougaar.install.path");

    // Keystore to store key pairs
    String defaultKeystorePath = installpath + File.separatorChar
      + "configs" + File.separatorChar + "common"
      + File.separatorChar + "keystore";
    ksPass = System.getProperty("org.cougaar.security.keystore.password","alpalp");
    ksPath = System.getProperty("org.cougaar.security.keystore", defaultKeystorePath);

    // CA keystore
    String defaultCaKeystorePath = installpath + File.separatorChar
      + "configs" + File.separatorChar + "common"
      + File.separatorChar + "keystoreCA";
    caksPass = System.getProperty("org.cougaar.security.cakeystore.password","alpalp");
    caksPath = System.getProperty("org.cougaar.security.cakeystore", defaultCaKeystorePath);

    // LDAP certificate directory
    provider_url = System.getProperty("org.cougaar.security.ldapserver", "ldap://localhost");

    if (debug) {
      System.out.println("Secure message keystore: path=" + ksPath);
      System.out.println("Secure message CA keystore: path=" + caksPath);
    }
    certificatefinder=new CertificateFinder(provider_url);
  }

  private static void init() {
    synchronized (initLock) {
      if (keystore == null) {
	try {
	  // Open Keystore
	  keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	  FileInputStream kss = new FileInputStream(ksPath);
	  keystore.load(kss, ksPass.toCharArray());

	  // Open CA keystore
	  cakeystore = KeyStore.getInstance(KeyStore.getDefaultType());
	  FileInputStream cakss = new FileInputStream(caksPath);
	  cakeystore.load(cakss, caksPass.toCharArray());

	  Enumeration alias = keystore.aliases();
	  if (debug) System.out.println("Keystore " + ksPath + " contains:");

	  while (alias.hasMoreElements()) {
	    try{
	      //build up the hashMap
	      String a = (String)alias.nextElement();
	      X509Certificate x=(X509Certificate)keystore.getCertificate(a);
	      m.put(x.getSubjectDN(), a);
	      if (debug) System.out.println(a);
	    }catch(Exception e)
	      {
		//e.printStackTrace();
	      }
	  }
	  kss.close();
	} catch (Exception e) {
	  e.printStackTrace();
	}
      }
    }
  }

  public static KeyStore getKeyStore() { 
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("getKeyStore"));
    }
    // Initialize if this has not been done already
    init();
    return keystore; 
  }

  public static PrivateKey getPrivateKey(String name) {
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("readPrivateKey"));
    }
    // Initialize if this has not been done already
    init();
    PrivateKey pk = null;
    try {
      synchronized (privateKeys) {
        pk = (PrivateKey) privateKeys.get(name);
        if (pk == null) {
          pk = (PrivateKey) keystore.getKey(name, ksPass.toCharArray());
	  if (pk == null) {
	    // Try with lower case.
	    pk = (PrivateKey) keystore.getKey(name.toLowerCase(), ksPass.toCharArray());
	    if (pk == null) {
	      // Key was not found in keystore either
	      if (debug) {
		System.out.println("No private key for " + name + " was found in keystore, generating...");
	      }
              //let's make our own key pair
              addKeyPair(name);
	    }
	  }
	  if (pk != null) {
	      privateKeys.put(name, pk);
	  }
        }
      }
    } catch (Exception e) {
      System.err.println("Failed to get PrivateKey for \""+name+"\": "+e);
      e.printStackTrace();
    }
    return pk;
  }

  public static Certificate getCert(Principal p) {
    String a = (String) m.get(p);
    return getCert(a, true);
  }

  public static Certificate getCert(String name) {
    return getCert(name, true);
  }

  /** Lookup a certificate. If lookupLDAP is true, search in the keystore only.
   * Otherwise, search in the keystore then in the LDAP directory service.
   */
  public static Certificate getCert(String name, boolean lookupLDAP) {
    // Initialize if this has not been done already
    init();
    
    Certificate cert = null;
    if (debug) {
      System.out.println("CertificateFinder.getCert(" + name + ")");
    }

    CertificateStatus certstatus=null;
    try {
      synchronized (certs) {
	// First, look in local hash map.
        Object o = certs.get(name);
	if(o != null) {
	  certstatus = (CertificateStatus)o;
	  if(lookupLDAP == false &&
	     certstatus.getCertificateOrigin() == CertificateStatus.CERT_LDAP) {
	    // Client does not want certificates that have been retrieved from
	    // the LDAP server.
	  }
	  else if(certstatus.isValid()) {
	    cert = certstatus.getCertificate();
	  }
	  if (debug) {
	    System.out.println("CertificateFinder.getCert. Found cert in local hash map:" + name );
	  }
	}
	else {
	  // Look in keystore file.
	  cert = keystore.getCertificate(name);
	  if(cert!=null) {
	    certstatus = new CertificateStatus(cert, true, CertificateStatus.CERT_KEYSTORE);
	    certs.put(name, certstatus);
	    if (debug) {
	      System.out.println("CertificateFinder.getCert. Found cert in keystore file:" + name );
	    }
	  }
	  else if (lookupLDAP == true) {
	    // Finally, look in certificate directory service
	    cert=certificatefinder.getCertificate(name);
	    if(cert!=null) {
	      certstatus = new CertificateStatus(cert, true, CertificateStatus.CERT_LDAP);
	      certs.put(name, certstatus);
              X509Certificate x = (X509Certificate)cert;
              m.put(x.getSubjectDN(), name);
	      if (debug) {
		System.out.println("CertificateFinder.getCert. Found cert in LDAP:" + name );
	      }
	    }	
	    else {
	      System.err.println("Failed to get Certificate for " + name);
	    }
	  }
	}
      }
    } catch (KeyStoreException e) {
      // Finally, look in certificate directory service
      if (lookupLDAP == true) {
	cert=certificatefinder.getCertificate(name);
	if(cert!=null) {
	  certstatus=new CertificateStatus(cert, true, CertificateStatus.CERT_LDAP);
	  certs.put(name,certstatus);
	  if (debug) {
	    System.out.println("CertificateFinder.getCert. Found cert in LDAP:" + name );
	  }
	}
      }	
      else {
	System.err.println("Failed to get Certificate for \""+name+"\": "+e);
      }
    }
    return cert;
  }

  /** Lookup Certificate Revocation Lists */
  public void run() {
    // Initialize if this has not been done already
    init();
    while(true) {
      try {
	Thread.sleep(sleep_time);
      }
      catch(InterruptedException interruptedexp) {
	interruptedexp.printStackTrace();
      }
      Hashtable crl=certificatefinder.getCRL();
      Enumeration enum=crl.keys();
      Certificate certificate=null;
      String alias=null;
      while(enum.hasMoreElements()) {
	alias=(String)enum.nextElement();
	certificate=(Certificate)crl.get(alias);
	CertificateStatus wrapperobject = new CertificateStatus(certificate, false, 0);
	if (debug) {
	  System.out.println("CertificateFinder.run. Adding CRL for " + alias );
	}
	certs.put(alias,wrapperobject);
        //make sure keystore is updated
        try{
	  keystore.deleteEntry(alias);
	  X509Certificate x = (X509Certificate)certificate;
	  m.remove(x.getSubjectDN());
        }catch(Exception e)
        { e.printStackTrace();}
      }
    }
  }

  public static void setSleeptime(long sleeptime)
  {
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("writeCrlparam"));
    }
    sleep_time=sleeptime;
  }

  public static long getSleeptime()
  {
    return sleep_time;
  }

  public static Vector getCRL()
  {
    // Initialize if this has not been done already
    init();
    Hashtable crl=certificatefinder.getCRL();
    Enumeration enum=crl.keys();
    String alias=null;
    Vector crllist=new Vector();
    while(enum.hasMoreElements()) {
      alias=(String)enum.nextElement();
      // TODO: store CRL in permanent storage
      crllist.addElement(alias);
    }
    return crllist;
  }

  /** Install a PKCS7 reply received from a certificate authority
   */
  public void installPkcs7Reply(String alias, InputStream inputstream)
    throws CertificateException, KeyStoreException
  {
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("installPkcs7Reply"));
    }
    // Initialize if this has not been done already
    init();

    CertificateFactory cf = CertificateFactory.getInstance("X509");
    PrivateKey privatekey = getPrivateKey(alias);
    Certificate certificate = getCert(alias, false);
    if(certificate == null) {
      throw new CertificateException(alias + " has no certificate");
    }

    Collection collection = cf.generateCertificates(inputstream);
    if(collection.isEmpty()) {
      throw new CertificateException("Reply has no certificate");
    }

    Certificate certificateReply[] = (Certificate[])collection.toArray();
    Certificate certificateForImport[];

    if(certificateReply.length == 1) {
      // The PKCS7 reply does not include the certificate chain.
      // We have to construct the chain first.
      certificateForImport = establishCertChain(certificate, certificateReply[0]);
    }
    else {
      // The PKCS7 reply contains the certificate chain.
      // Validate the chain before proceeding.
      certificateForImport = validateReply(alias, certificate, certificateReply);
    }
    if(certificateForImport != null) {
	keystore.setKeyEntry(alias, privatekey, ksPass.toCharArray(), certificateForImport);
    }
  }

  private Certificate[] establishCertChain(Certificate certificate,
					   Certificate certificateReply)
    throws CertificateException, KeyStoreException
  {
    if(certificate != null) {
      java.security.PublicKey publickey = certificate.getPublicKey();
      java.security.PublicKey publickey1 = certificateReply.getPublicKey();
      if(!publickey.equals(publickey1)) {
	String s = "Public keys in reply and keystore don't match";
	throw new CertificateException(s);
      }
      if(certificateReply.equals(certificate)) {
	String s1 = "Certificate reply and certificate in keystore are identical";
	throw new CertificateException(s1);
      }
    }

    Hashtable hashtable = null;
    if(keystore.size() > 0) {
      hashtable = new Hashtable(11);
      keystorecerts2Hashtable(keystore, hashtable);
    }

    if(cakeystore != null && cakeystore.size() > 0) {
      if(hashtable == null)
	hashtable = new Hashtable(11);
      keystorecerts2Hashtable(cakeystore, hashtable);
    }

    Vector vector = new Vector(2);
    if(buildChain((X509Certificate)certificateReply, vector, hashtable)) {
      Certificate acertificate[] = new Certificate[vector.size()];
      int i = 0;
      for(int j = vector.size() - 1; j >= 0; j--) {
	acertificate[i] = (Certificate)vector.elementAt(j);
	i++;
      }
      return acertificate;
    } else {
      throw new CertificateException("Failed to establish chain from reply");
    }
  }


  private void keystorecerts2Hashtable(KeyStore aKeystore, Hashtable hashtable)
    throws KeyStoreException
  {
    for(Enumeration enumeration = aKeystore.aliases(); enumeration.hasMoreElements(); ) {
      String s = (String)enumeration.nextElement();
      Certificate certificate = aKeystore.getCertificate(s);
      if(certificate != null) {
	Principal principal = ((X509Certificate)certificate).getSubjectDN();
	Vector vector = (Vector)hashtable.get(principal);
	if(vector == null) {
	  vector = new Vector();
	  vector.addElement(certificate);
	} else
	  if(!vector.contains(certificate))
	    vector.addElement(certificate);
	hashtable.put(principal, vector);
      }
    }
  }


  private Certificate[] validateReply(String alias, Certificate certificate,
				      Certificate certificateReply[])
    throws CertificateException
  {
    java.security.PublicKey publickey = certificate.getPublicKey();
    int i;
    for(i = 0; i < certificateReply.length; i++)
      if(publickey.equals(certificateReply[i].getPublicKey()))
	break;

    if(i == certificateReply.length)
      throw new CertificateException("Certificate reply does not contain public key for <" + alias + ">");
    Certificate certificate1 = certificateReply[0];
    certificateReply[0] = certificateReply[i];
    certificateReply[i] = certificate1;
    Principal principal = ((X509Certificate)certificateReply[0]).getIssuerDN();
    for(int j = 1; j < certificateReply.length - 1; j++) {
      int l;
      for(l = j; l < certificateReply.length; l++) {
	Principal principal1 = ((X509Certificate)certificateReply[l]).getSubjectDN();
	if(!principal1.equals(principal))
	  continue;
	Certificate certificate2 = certificateReply[j];
	certificateReply[j] = certificateReply[l];
	certificateReply[l] = certificate2;
	principal = ((X509Certificate)certificateReply[j]).getIssuerDN();
	break;
      }

      if(l == certificateReply.length)
	throw new CertificateException("Incomplete certificate chain in reply");
    }

    for(int k = 0; k < certificateReply.length - 1; k++) {
      java.security.PublicKey publickey1 = certificateReply[k + 1].getPublicKey();
      try {
	certificateReply[k].verify(publickey1);
      }
      catch(Exception exception) {
	throw new CertificateException("Certificate chain in reply does not verify: " + exception.getMessage());
      }
    }
    return certificateReply;
  }


  private boolean buildChain(X509Certificate x509certificate, Vector vector, Hashtable hashtable)
  {
    Principal principal = x509certificate.getSubjectDN();
    Principal principal1 = x509certificate.getIssuerDN();
    if(principal.equals(principal1)) {
      vector.addElement(x509certificate);
      return true;
    }
    Vector vector1 = (Vector)hashtable.get(principal1);
    if(vector1 == null)
      return false;
    Enumeration enumeration = vector1.elements();
    while(enumeration.hasMoreElements()) {
      X509Certificate x509certificate1 = (X509Certificate)enumeration.nextElement();
      java.security.PublicKey publickey = x509certificate1.getPublicKey();
      try {
	x509certificate.verify(publickey);
      }
      catch(Exception exception) {
	continue;
      }
      if(buildChain(x509certificate1, vector, hashtable)) {
	vector.addElement(x509certificate);
	return true;
      }
    }
    return false;
  }

  /** Generate a PKCS10 request from a public key */
  public static byte[] generateSigningCertificateRequest(PublicKey key) {
    PKCS10 request = new PKCS10(key);
    return request.getEncoded();
  }
  
  /**add keys to the key ring**/
  private static void addKeyPair(String name){
      //is node?
      String nodeName = System.getProperty("org.cougaar.node.name");
      if(name==nodeName){
          //we're node
          KeyPair kp = makeKeys();
          //send the public key to the ca
          PublicKey pk = kp.getPublic();
          byte[] request;
          request = generateSigningCertificateRequest(pk);
          
      }else{
          //check if node cert exist
          if(certs.get(name)==null){
              //we don't have a node key pair, so make it
              addKeyPair(nodeName);
          }else{
              KeyPair kp = makeKeys();
              
          }
      }
      return;
  }
  
  /**make a pair of keys**/
  private static KeyPair makeKeys(){
      KeyPairMaker kpm = new KeyPairMaker();
      return kpm.makeKeyPair();
  }
}

