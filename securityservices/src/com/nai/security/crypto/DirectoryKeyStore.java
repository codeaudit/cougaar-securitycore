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

package com.nai.security.crypto;

import java.io.*;
import java.util.*;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Principal;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.cert.*;
import java.security.KeyPair;
import java.security.SecureRandom;

import sun.security.pkcs.*;
import sun.security.x509.*;

import org.cougaar.util.ConfigFinder;
import com.nai.security.certauthority.CAClient;
import com.nai.security.certauthority.KeyManagement;
import com.nai.security.policy.NodePolicy;

public class DirectoryKeyStore implements Runnable
{
  private KeyStore keystore = null;
  private char[] keystorePassword = null;
  private String keystorePath = null;

  private KeyStore caKeystore = null;
  private char[] caKeystorePassword = null;
  private String caKeystorePath = null;

  private String provider_url=null;
  private CertificateFinder certificatefinder=null;
  private long sleep_time=2000l; 
  private boolean debug = false;
  private HashMap m = new HashMap();

  // A hash map to store the private keys, indexed with common name
  private HashMap privateKeysAlias = new HashMap(89);

  // A hash map to store public keys, indexed with common name
  private HashMap certsAlias = new HashMap(89);

  // A hash map to quickly find an alias given a common name
  private HashMap commonName2alias = new HashMap(89);

  private CAClient caClient = null;

  public DirectoryKeyStore(String ldapURL,
			   InputStream stream, char[] password, String storepath,
			   InputStream caStream, char[] caPassword, String caStorepath) {
    this(stream, password, storepath, caStream, caPassword, caStorepath);
    // LDAP certificate directory
    provider_url = ldapURL;
    certificatefinder = new CertificateFinder(provider_url);
  }

  public DirectoryKeyStore(InputStream stream, char[] password, String storepath,
			   InputStream caStream, char[] caPassword, String caStorepath) {
    init(stream, password, storepath, caStream, caPassword, caStorepath);
  }

  private void init(InputStream stream, char[] password, String storepath,
		    InputStream caStream, char[] caPassword, String caStorepath) {
    try {
      debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						  "false"))).booleanValue();

      // Open Keystore
      keystorePassword = password;
      keystorePath = storepath;
      keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      keystore.load(stream, password);

      // Initialize commonName2alias hash map
      initCN2aliasMap();

      // Open CA keystore
      if (caStream != null) {
	caKeystorePassword = caPassword;
	caKeystorePath = caStorepath;
	caKeystore = KeyStore.getInstance(KeyStore.getDefaultType());
	try {
	  caKeystore.load(caStream, caPassword);
	} catch (Exception e) {
	  // Unable to use CA keystore. Do not use it
	  caKeystore = null;
	  caKeystorePassword = null;
	}
      }
      if (debug) {
	listKeyStoreAlias(keystore, keystorePath);
	listKeyStoreAlias(caKeystore, caKeystorePath);
      }
      caClient = new CAClient();

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void listKeyStoreAlias(KeyStore ks, String path) {
    try {
      Enumeration alias = ks.aliases();

      System.out.println("Keystore " + path + " contains:");
      while (alias.hasMoreElements()) {
	//build up the hashMap
	String a = (String)alias.nextElement();
	X509Certificate x=(X509Certificate)ks.getCertificate(a);
	m.put(x.getSubjectDN(), a);
	System.out.println("  " + a);
      }
    } catch(Exception e) {
      System.out.println(e);
      e.printStackTrace();
    }
  }

  public KeyStore getKeyStore() { 
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("getKeyStore"));
    }
    return keystore; 
  }

  public synchronized PrivateKey findPrivateKey(String commonName) {
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("readPrivateKey"));
    }
    PrivateKey pk = null;
    String alias = (String) commonName2alias.get(commonName);
    if (alias == null) {
      // Key does not exist in keystore
    }
    try {
      // First, try with the hash map (cache)
      pk = (PrivateKey) privateKeysAlias.get(commonName);
      if (pk != null && debug) {
	System.out.println("Found private key in hash map");
      }
      if (pk == null && alias != null) {
	// Then try with the key store file
	pk = (PrivateKey) keystore.getKey(alias, keystorePassword);
	if (debug) {
	  System.out.println("Found private key in keystore");
	}
      }
      if (pk == null && alias != null) {
	// Try with lower case.
	pk = (PrivateKey) keystore.getKey(alias.toLowerCase(), keystorePassword);
	if (debug) {
	  System.out.println("Found private key in keystore");
	}
      }
      if (pk == null) {
	// Key was not found in keystore either.
	if (debug) {
	  System.out.println("No private key for " + commonName
			     + " was found in keystore, generating...");
	}
	//let's make our own key pair
	pk = addKeyPair(commonName);
      }
      if (pk != null) {
	privateKeysAlias.put(commonName, pk);
      }
    } catch (Exception e) {
      System.err.println("Failed to get PrivateKey for \"" + commonName + "\": "+e);
      e.printStackTrace();
    }
    return pk;
  }

  /** Lookup a certificate. If lookupLDAP is true, search in the keystore only.
   * Otherwise, search in the keystore then in the LDAP directory service.
   */
  public synchronized Certificate findCert(String commonName, boolean lookupLDAP) {
    Certificate cert = null;
    if (debug) {
      System.out.println("CertificateFinder.getCert(" + commonName + ")");
    }

    CertificateStatus certstatus=null;
    String alias = (String) commonName2alias.get(commonName);
    if (alias == null) {
      // Key does not exist in keystore
    }

    try {
      // First, look in the local hash map.
      Object o = certsAlias.get(commonName);
      if(o != null) {
	certstatus = (CertificateStatus)o;
	if(lookupLDAP == false &&
	   certstatus.getCertificateOrigin() == CertificateStatus.CERT_LDAP) {
	  // The client is requesting to get certificates only from the keystore
	  // (not those from the LDAP server.
	}
	else if(certstatus.isValid()) {
	  cert = certstatus.getCertificate();
	}
	if (debug) {
	  System.out.println("CertificateFinder.getCert. Found cert in local hash map:"
			     + commonName );
	}
      }
      else {
	// Look in keystore file.
	if (alias != null) {
	  cert = keystore.getCertificate(alias);
	  certstatus = new CertificateStatus(cert, true, CertificateStatus.CERT_KEYSTORE);
	  certsAlias.put(commonName, certstatus);
	  if (debug) {
	    System.out.println("CertificateFinder.getCert. Found cert in keystore file:"
			       + commonName );
	  }
	}
	else if (lookupLDAP == true) {
	  // Finally, look in certificate directory service
	  cert=certificatefinder.getCertificate(commonName);
	  if(cert!=null) {
	    certstatus = new CertificateStatus(cert, true, CertificateStatus.CERT_LDAP);
	    certsAlias.put(commonName, certstatus);
	    X509Certificate x = (X509Certificate)cert;
	    m.put(x.getSubjectDN(), commonName);
	    if (debug) {
	      System.out.println("CertificateFinder.getCert. Found cert in LDAP:"
				 + commonName );
	    }
	  }	
	  else {
	    System.err.println("Failed to get Certificate for " + commonName);
	  }
	}
      }
    } catch (KeyStoreException e) {
      // Finally, look in certificate directory service
      if (lookupLDAP == true) {
	cert=certificatefinder.getCertificate(commonName);
	if(cert!=null) {
	  certstatus=new CertificateStatus(cert, true, CertificateStatus.CERT_LDAP);
	  certsAlias.put(commonName,certstatus);
	  if (debug) {
	    System.out.println("CertificateFinder.getCert. Found cert in LDAP:"
			       + commonName );
	  }
	}
      }	
      else {
	System.err.println("Failed to get Certificate for \""
			   + commonName + "\": " + e);
      }
    }
    return cert;
  }

  /** Lookup Certificate Revocation Lists */
  public void run() {
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
	certsAlias.put(alias, wrapperobject);
        //make sure keystore is updated
        try{
	  deleteEntry(alias);
	  X509Certificate x = (X509Certificate)certificate;
	  m.remove(x.getSubjectDN());
        } catch(Exception e) {
	  e.printStackTrace();
	}
      }
    }
  }

  public void setSleeptime(long sleeptime)
  {
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("writeCrlparam"));
    }
    sleep_time=sleeptime;
  }

  public long getSleeptime()
  {
    return sleep_time;
  }

  public Vector getCRL()
  {
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
    throws CertificateException, KeyStoreException, NoSuchAlgorithmException,
	   UnrecoverableKeyException
  {

    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("installPkcs7Reply"));
    }

    if (debug) {
      System.out.println("installPkcs7Reply for " + alias);
    }
    CertificateFactory cf = CertificateFactory.getInstance("X509");
    PrivateKey privatekey = (PrivateKey) keystore.getKey(alias, keystorePassword);
    Certificate certificate = keystore.getCertificate(alias);
    if(certificate == null) {
      throw new CertificateException(alias + " has no certificate");
    }

    Collection collection = cf.generateCertificates(inputstream);
    if(collection.isEmpty()) {
      throw new CertificateException("Reply has no certificate");
    }
    if (debug) {
      Iterator it = collection.iterator();
      while (it.hasNext()) {
	System.out.println( ((Certificate)it.next()).toString() );
      }
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
	setKeyEntry(alias, privatekey, certificateForImport);
    }
  }

  private String getCommonName(X509Certificate x509)
  {
    String cn = null;
    X500Name clientX500Name;
    try {
      clientX500Name = new X500Name(x509.getSubjectDN().toString());
      cn = clientX500Name.getCommonName();
    } catch(Exception e) {
      System.out.println("Unable to get Common Name - " + e);
    }
    return cn;
  }

  private void addCN2alias(String alias, Certificate aCertificate)
  {
    X509Certificate x509 = (X509Certificate)aCertificate;
    String cn = getCommonName(x509);
    if (debug) {
      System.out.println("addCN2alias: " + cn + "<->" + alias);
    }
    commonName2alias.put(cn, alias);
  }

  private void removeCN2alias(String cn)
  {
    String alias = (String) commonName2alias.get(cn);
    if (debug) {
      System.out.println("removeCN2alias: " + cn + "<->" + alias);
    }
    commonName2alias.remove(cn);
  }

  /** Set a key entry in the keystore */
  private void setKeyEntry(String alias, PrivateKey privatekey,
			   Certificate[] certificateForImport)
  {
    addCN2alias(alias, (X509Certificate)certificateForImport[0]);
    try {
      keystore.setKeyEntry(alias, privatekey, keystorePassword, certificateForImport);
    } catch(Exception e) {
      System.out.println("Unable to set key entry in the keystore - "
			 + e.getMessage());
    }
    // Store key store in permanent storage.
    storeKeyStore();
  }

  private void setCertificateEntry(String alias, Certificate aCertificate)
  {
    addCN2alias(alias, (X509Certificate)aCertificate);
    try {
      keystore.setCertificateEntry(alias, aCertificate);
    } catch(Exception e) {
      System.out.println("Unable to set certificate in the keystore - "
			 + e.getMessage());
    }
    // Store key store in permanent storage.
    storeKeyStore();
  }

  private void deleteEntry(String alias)
  {
    removeCN2alias(alias);
    try {
      keystore.deleteEntry(alias);
    } catch(Exception e) {
      System.out.println("Unable to set certificate in the keystore - "
			 + e.getMessage());
    }

    // Store key store in permanent storage.
    storeKeyStore();
  }

  /** Store the keystore in permanent storage. Should be called anytime
      a key is modified, created or deleted. */
  private void storeKeyStore()
  {
    if (debug) {
      System.out.println("Storing keystore in permanent storage");
    }
    try {
      FileOutputStream out = new FileOutputStream(keystorePath);
      keystore.store(out, keystorePassword);
      out.flush();
      out.close();
    } catch(Exception e) {
      System.out.println("Error: can't flush the certificate to the keystore--"
			 + e.getMessage());
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

    if(caKeystore != null && caKeystore.size() > 0) {
      if(hashtable == null)
	hashtable = new Hashtable(11);
      keystorecerts2Hashtable(caKeystore, hashtable);
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
	throw new CertificateException("Certificate chain in reply does not verify: "
				       + exception.getMessage());
      }
    }
    return certificateReply;
  }


  private boolean buildChain(X509Certificate x509certificate, Vector vector,
			     Hashtable hashtable)
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
  public String generateSigningCertificateRequest(Certificate certificate,
						  String signerAlias)
    throws IOException, SignatureException, NoSuchAlgorithmException, InvalidKeyException,
	   KeyStoreException, UnrecoverableKeyException
  {
    PublicKey pk = certificate.getPublicKey();
    PKCS10 request = new PKCS10(pk);

    // Get Signature object for certificate authority
    PrivateKey signerPrivateKey = (PrivateKey) keystore.getKey(signerAlias, keystorePassword);
    X509Certificate cert = (X509Certificate)keystore.getCertificate(signerAlias);
    Signature signerSignature = Signature.getInstance(signerPrivateKey.getAlgorithm());
    signerSignature.initSign(signerPrivateKey);

    X500Name signerX500Name = new X500Name(cert.getSubjectDN().toString());
    X500Signer x500signer = new X500Signer(signerSignature, signerX500Name);

    try {
      if (debug) {
	System.out.println("Signing certificate request with alias=" + signerAlias);
      }
      request.encodeAndSign(x500signer);
    }
    catch (CertificateException e) {
      System.out.println("Unable to sign certificate request." + e);
    }
    byte der[] = request.getEncoded();
    System.out.println("generateSigningCertificateRequest. der size:" + der.length);
    char base64req[] = Base64.encode(der);
    String reply = KeyManagement.PKCS10HEADER
      + new String(base64req) + KeyManagement.PKCS10TRAILER;
    return reply;
  }

  /** Get a list of all the certificates in the keystore */
  private Key[] getCertificates()
  {
    Enumeration en = null;
    try {
      en = keystore.aliases();
    }
    catch (KeyStoreException e) {
      System.out.println("Unable to get list of aliases in keystore");
      return null;
    }

    ArrayList certificateList = new ArrayList();

    while(en.hasMoreElements()) {
      String alias = (String)en.nextElement();
      try {
	Certificate c = keystore.getCertificate(alias);
	Key key = new Key(c, alias);
	certificateList.add(key);
      }
      catch (KeyStoreException e) {
	System.out.println("Unable to get certificate for " + alias);
      }
    }
    Key[] keyReply = new Key[certificateList.size()];
    for (int i = 0 ; i < certificateList.size() ; i++) {
      keyReply[i] = (Key) certificateList.get(i);
    }

    return keyReply;
  }

  /** Add keys to the key ring **/
  private synchronized PrivateKey addKeyPair(String commonName){
    String request = "";
    String reply = "";
    //is node?
    String nodeName = System.getProperty("org.cougaar.node.name");
    String alias = null;
    PrivateKey privatekey = null;
    try {
      if(commonName == nodeName){
	// We are node
	if (debug) {
	  System.out.println("Creating key pair for node: " + nodeName);
	}
	alias = makeKeyPair(commonName);
	// Send the public key to the Certificate Authority (PKCS10)
	request = generateSigningCertificateRequest(keystore.getCertificate(alias), alias);
	if (debug) {
	  System.out.println("Sending PKCS10 request to CA");
	}
	reply = caClient.sendPKCS(request, "PKCS10");
      } else {
	// check if node cert exist
	X509Certificate nodex509 = (X509Certificate) findCert(nodeName);
	if(nodex509 == null) {
	  //we don't have a node key pair, so make it
	  if (debug) {
	    System.out.println("Recursively creating key pair for node: " + nodeName);
	  }
	  addKeyPair(nodeName);
	}
	nodex509 = (X509Certificate) findCert(nodeName);
	// Node key should exist now
	if (debug) {
	  System.out.println("Creating key pair for agent: " + commonName);
	}
	alias = makeKeyPair(commonName);
	// Generate a pkcs10 request, then sign it with node's key
	//String nodeAlias = findAlias(nodeName);
	request = generateSigningCertificateRequest(keystore.getCertificate(alias), alias);
	// Sign PKCS10 request with node key and send agent cert to CA

	reply = caClient.signPKCS(request, nodex509.getSubjectDN().getName());
      }
    } catch (Exception e) {
      System.out.println("Unable to create key: " + commonName + " - Reason:" + e);
      e.printStackTrace();
    }
    if (alias != null) {
      try{ 
	installPkcs7Reply(alias, new ByteArrayInputStream(reply.getBytes()));
	privatekey = (PrivateKey) keystore.getKey(alias, keystorePassword);
      } catch(Exception e) {
	System.err.println("Error: can't get certificate for " + commonName);
	e.printStackTrace();
      }
    }
    return privatekey;
  }

  public String getAlias(X509Certificate clientX509) 
  {
    String alias = null;
    try {
      String alg = "MD5"; // TODO: make this dynamic
      MessageDigest md = createDigest(alg, clientX509.getTBSCertificate());
      byte[] digest = md.digest();
      
      String prefix = getCommonName(clientX509);
      alias = prefix + "-" + toHex(digest);
    }
    catch (Exception e) {
      System.out.println("Unable to get alias: " + e);
      e.printStackTrace();
    }
    return alias;
  }

  public Certificate findCert(Principal p) {
    String a = (String) m.get(p);
    return findCert(a, true);
  }

  public Certificate findCert(String name) {
    return findCert(name, true);
  }

  /*
  public X509Certificate findCert(String commonName, boolean lookupLDAP) {
    String alias = (String) commonName2alias.get(commonName);
    X509Certificate x509 = (X509Certificate) getCert(alias, lookupLDAP);
    return x509;
  }
  */
  /*
  public PrivateKey findPrivateKey(String commonName) {
    String alias = (String) commonName2alias.get(commonName);
    PrivateKey pk = getPrivateKey(alias);
    return pk;
  }
  */

  private void initCN2aliasMap()
  {
    Key[] keys = getCertificates();
    for (int i = 0 ; i < keys.length ; i++) {
      if (keys[i].cert instanceof X509Certificate) {
	X509Certificate aCert = (X509Certificate) keys[i].cert;
	X500Name dname = null;
	try {
	  dname = new X500Name(aCert.getSubjectDN().getName());
	  commonName2alias.put(dname.getCommonName(), keys[i].alias);
	}
	catch (Exception e) {
	  System.out.println("Unable to initialize commonName2alias:" + e);
	  e.printStackTrace();
	}
      }
    }
    if (debug) {
      Set st = commonName2alias.keySet();
      Iterator it = st.iterator();
      System.out.println("CommonName to Alias Hash map contains:");
      while (it.hasNext()) {
	String cn = (String) it.next();
	System.out.println("cn=" + cn + " <-> " + commonName2alias.get(cn));
      }
    }
  }

  private String findAlias(String commonName) {
    Key[] keys = getCertificates();
    String alias = null;
    for (int i = 0 ; i < keys.length ; i++) {
      if (keys[i].cert instanceof X509Certificate) {
	X509Certificate aCert = (X509Certificate) keys[i].cert;
	X500Name dname = null;
	try {
	  dname = new X500Name(aCert.getSubjectDN().getName());
	  if (commonName.equals(dname.getCommonName())) {
	    return keys[i].alias;
	  }
	}
	catch (Exception e) {
	  System.out.println("Unable to find cert:"+ e);
	  e.printStackTrace();
	}
      }
    }
    return alias;
  }

  private MessageDigest createDigest(String algorithm, byte[] data)
    throws NoSuchAlgorithmException
  {
    MessageDigest md = MessageDigest.getInstance(algorithm);

    // Create a digest
    md.reset();
    md.update(data);
    md.digest();
    return md;
  }
    
  private String toHex(byte[] data) {
    StringBuffer buff = new StringBuffer();
    for(int i = 0; i < data.length; i++) {
      String digit = Integer.toHexString(data[i] & 0x00ff);
      if(digit.length() < 2)buff.append("0");
      buff.append(digit);
    }
    return buff.toString();
  }

  public String makeKeyPair(String commonName)
    throws Exception 
  {
    //generate key pair.
    NodePolicy policy = caClient.getNodePolicy();
    SecureRandom sr = new SecureRandom();
    byte bytes[] = new byte[10];
    sr.nextBytes(bytes);
    String rdm = toHex(bytes);
    // TODO: find a better alias name
    String alias = commonName + "-" + rdm;
    if (debug) {
      System.out.println("Make key pair for alias=" + alias + ", cn=" + commonName + ", ou=" 
			 + policy.ou + ",o=" +  policy.o + ",l=" + policy.l
			 + ",st=" + policy.st + ",c=" + policy.c);
    }
    X500Name dname = new X500Name(commonName,
				  policy.ou, policy.o, policy.l, policy.st, policy.c);
    doGenKeyPair(alias, dname.getName(), policy.keyAlgName,
		 policy.keysize, policy.sigAlgName,
		 policy.validity);
    return alias;
  }

  public void doGenKeyPair(String alias, String dname,
			   String keyAlgName, int keysize, String sigAlgName,
			   int validity)
    throws Exception
  {
    if(sigAlgName == null)
      if(keyAlgName.equalsIgnoreCase("DSA"))
	sigAlgName = "SHA1WithDSA";
      else
	if(keyAlgName.equalsIgnoreCase("RSA"))
	  sigAlgName = "MD5WithRSA";
	else
	  throw new Exception("Cannot derive signature algorithm");
    CertAndKeyGen certandkeygen = new CertAndKeyGen(keyAlgName, sigAlgName);
    X500Name x500name;
    x500name = new X500Name(dname);
    if (debug) {
      System.out.println("Generating " + keysize + " bit " + keyAlgName
			 + " key pair and " + "self-signed certificate (" + sigAlgName + ")");
      System.out.println("\tfor: " + x500name + " - alias:" + alias);
    }
    certandkeygen.generate(keysize);
    PrivateKey privatekey = certandkeygen.getPrivateKey();
    X509Certificate ax509certificate[] = new X509Certificate[1];
    ax509certificate[0] = certandkeygen.getSelfCertificate(x500name, validity * 24 * 60 * 60);
    setKeyEntry(alias, privatekey, ax509certificate);
  }
}
