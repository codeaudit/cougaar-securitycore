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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Principal;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.*;
import java.security.KeyPair;
import java.security.SecureRandom;

import java.security.SignatureException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyStoreException;

import sun.security.pkcs.*;
import sun.security.x509.*;

import org.cougaar.util.ConfigFinder;
import com.nai.security.certauthority.CAClient;
import com.nai.security.certauthority.KeyManagement;
import com.nai.security.policy.NodePolicy;
import com.nai.security.policy.CaPolicy;
import com.nai.security.util.*;
import com.nai.security.crypto.ldap.CertDirectoryServiceClient;
import com.nai.security.crypto.ldap.CertDirectoryServiceFactory;
import com.nai.security.crypto.ldap.LdapEntry;

public class DirectoryKeyStore implements Runnable
{
  /** This keystore stores the following keys:
   *  - Keys that have been introduced through the automated key pair generation process.
   *  - (Optional) Keys that have been manually installed during Cougaar installation
   *    This may include key pairs for a Cougaar entity (user, node, agent, ...) as
   *    well as certificates from other entities.
   */
  private KeyStore keystore = null;

  /** This keystore stores certificates of trusted certificate authorities. */
  private KeyStore caKeystore = null;

  private CertDirectoryServiceClient certificateFinder=null;
  private long sleep_time=2000l; 
  private boolean debug = false;

  /** A hash map to store the private keys, indexed with common name */
  //private HashMap privateKeysAlias = new HashMap(89);

  /** A hash map to store certificates from keystore, caKeystore and the LDAP directory
      service, indexed by distinguished name */
  private CertificateCache certCache = null;

  /** A hash map to quickly find an alias given a common name */
  private HashMap commonName2alias = new HashMap(89);

  private CAClient caClient = null;

  private String defaultOrganizationUnit = null;
  private String defaultOrganization = null;
  private String defaultLocality = null;
  private String defaultState = null;
  private String defaultCountry = null;
  private String defaultKeyAlgName = null;
  private int defaultKeysize = 0;
  private long defaultValidity = 0;
  private String defaultSigAlgName = null;
  private DirectoryKeyStoreParameters param = null;

  /** Initialize the directory key store */
  public DirectoryKeyStore(DirectoryKeyStoreParameters aParam) {
    try {
      debug =
	(Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
					    "false"))).booleanValue();

      param = aParam;

      // Load crypto providers
      CryptoProviders.loadCryptoProviders();

      // LDAP certificate directory
      certificateFinder =
	CertDirectoryServiceFactory.getCertDirectoryServiceClientInstance(
	        param.ldapServerType, param.ldapServerUrl);		      

      // Open Keystore
      keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      keystore.load(param.keystoreStream, param.keystorePassword);

      // Open CA keystore
      if (param.caKeystoreStream != null) {
	caKeystore = KeyStore.getInstance(KeyStore.getDefaultType());
	try {
	  caKeystore.load(param.caKeystoreStream, param.caKeystorePassword);
	} catch (Exception e) {
	  // Unable to use CA keystore. Do not use it
	  caKeystore = null;
	  param.caKeystorePassword = null;
	}
      }

      // Initialize commonName2alias hash map
      initCN2aliasMap();

      if (debug) {
	listKeyStoreAlias(keystore, param.keystorePath);
	listKeyStoreAlias(caKeystore, param.caKeystorePath);
      }

      if (!param.standalone) {
	// We running as part of Cougaar, this class may be used to support
	// certificate authority services. In that cases, we need CA policy
	String role = System.getProperty("org.cougaar.security.role"); 
	if (role == null && debug == true) {
	  System.out.println("DirectoryKeystore warning: LDAP role not defined");
	}
	caClient = new CAClient(role);
        //the KAoS domain manager runs a plugin, check if it has a cert
        //String dn = System.getProperty("org.cougaar.domain.manager");
        //if(dn!=null) checkOrMakeCert(dn);
	NodePolicy nodePolicy = caClient.getNodePolicy();

	defaultOrganizationUnit = nodePolicy.ou;
	defaultOrganization = nodePolicy.o;
	defaultLocality = nodePolicy.l;
	defaultState = nodePolicy.st;
	defaultCountry = nodePolicy.c;
	defaultKeyAlgName = nodePolicy.keyAlgName;
	defaultKeysize = nodePolicy.keysize;
	defaultValidity = nodePolicy.howLong;
	defaultSigAlgName = nodePolicy.sigAlgName;
      }
      else {
	// Standalone
      }

      // Initialize certificate cache
      initCertCache();

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /** Dump all the key aliases in a keystore */
  private void listKeyStoreAlias(KeyStore ks, String path) {
    if (ks == null) {
      if (debug) {
	System.out.println("listKeyStoreAlias. Null keystore");
      }
      return;
    }
    try {
      Enumeration alias = ks.aliases();

      System.out.println("Keystore " + path + " contains:");
      while (alias.hasMoreElements()) {
	//build up the hashMap
	String a = (String)alias.nextElement();
	X509Certificate x=(X509Certificate)ks.getCertificate(a);
	//m2.put(x.getSubjectDN(), a);
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

    // First, try with the hash map (cache)
    pk = certCache.getPrivateKeyByCommonName(commonName);

    if (pk != null && debug) {
      System.out.println("Found private key in hash map");
    }

    if (pk == null) {
      // Key was not found in keystore either.
      if (debug) {
	System.out.println("No private key for " + commonName
			   + " was found in keystore, generating...");
      }
      if (!param.standalone) {
	//let's make our own key pair
	pk = addKeyPair(commonName, null);
      }
    }
    /* Now, we have a private key. However, the key may not be valid for the
     * following reasons:
     *   + the key has expired
     *   + the key was generated, but we couldn't get it signed from the CA
     */
    return pk;
  }

  public static final int LOOKUP_LDAP               = 1;
  public static final int LOOKUP_KEYSTORE           = 2;
  public static final int LOOKUP_FORCE_LDAP_REFRESH = 4;

  /** Lookup a certificate.
   * LOOKUP_LDAP set: Lookup in LDAP directory service.
   * LOOKUP_KEYSTORE: Lookup in keystore file.
   * LOOKUP_FORCE_LDAP_REFRESH: Force a new lookup in the LDAP service.
  */
  public synchronized Certificate findCert(String commonName,
					   int lookupType)
  throws Exception
  {
    Certificate cert = null;
    if (debug) {
      System.out.println("DirectoryKeyStore.findCert(" + commonName
			 + ") lookup type=" + lookupType);
    }
    if (commonName == null) {
      throw new Exception("Common Name is null");
    }

    CertificateStatus certstatus=null;

    /*
    String alias = (String) commonName2alias.get(commonName);
    if (alias == null) {
      // Key does not exist in keystore
      if (debug) {
	System.out.println("Certificate [" + commonName
			   + "] not in key store");
	listKeyStoreAlias(keystore, keystorePath);
      }
    }
    */

    // Refresh from LDAP service if requested
    if ((lookupType & LOOKUP_FORCE_LDAP_REFRESH) != 0) {
      // Update cache with certificates from LDAP.
      String filter = "(cn=" + commonName + ")";
      lookupCertInLDAP(filter);
      certstatus = certCache.getCertificateByCommonName(commonName);
      if (certstatus != null) {
	cert = certstatus.getCertificate();
      }
    }

    // Search in the local hash map.
    certstatus = certCache.getCertificateByCommonName(commonName);
    if(certstatus != null) {
      if((lookupType & LOOKUP_LDAP) != 0 &&
	 certstatus.getCertificateOrigin() == CertificateOrigin.CERT_ORI_LDAP) {
	// The caller accepts certificates from LDAP.
	cert = certstatus.getCertificate();
      }
      else if ((lookupType & LOOKUP_KEYSTORE) != 0 &&
	 certstatus.getCertificateOrigin() == CertificateOrigin.CERT_ORI_KEYSTORE) {
	// The caller accepts certificates from the keystore.
	cert = certstatus.getCertificate();
      }
    }
    else {
      if ((lookupType & LOOKUP_FORCE_LDAP_REFRESH) != 0) {
	// We have just tried to lookup in LDAP so don't bother retrying again
      }
      else {
	// Look up in certificate directory service
	if ((lookupType & LOOKUP_LDAP) != 0) {
	  String filter = "(cn=" + commonName + ")";
	  lookupCertInLDAP(filter);
	  certstatus = certCache.getCertificateByCommonName(commonName);
	  if (certstatus != null) {
	    cert = certstatus.getCertificate();
	  }
	}
      }
    }
    if (debug) {
      if (cert != null) {
	System.out.println("DirectoryKeyStore.findCert: " + commonName
			   + " - Cert origin: " + certstatus.getCertificateOrigin());
      }
      else {
	System.out.println("DirectoryKeyStore.findCert: " + commonName + " not found");
      }
    }

    return cert;
  }

  /** Lookup a certificate in the LDAP directory service.
   * A search filter is needed.
   * Examples of search filters:
   *     (cn=agent_name)
   *     (dn=distinguished_name)
   */
  private void lookupCertInLDAP(String filter)
  {
    LdapEntry[] certs = null;
    CertificateStatus certstatus=null;
    // Look in certificate directory service
    if (debug) {
      System.out.println("DirectoryKeyStore.findCert. Looking up ["
			 + filter + " ] in LDAP");
    }
    if (certificateFinder != null) {
      //String filter = "(cn=" + commonName + ")";
      certs = certificateFinder.searchWithFilter(filter);
    }
    if (certs.length == 0) {
      if (debug) {
	System.err.println("Failed to get Certificate for " + filter);
      }
    }

    for (int i = 0 ; i < certs.length ; i++) {
      // Since the certificate comes from an LDAP server, it should be trusted
      // (because only a CA should publish certificates to the directory service,
      // but let's check just to make sure. There may be some cases where
      // a particular CA is not trusted locally.
      try {
	Certificate[] certChain = checkCertificateTrust(certs[i].getCertificate());
	certstatus = new CertificateStatus(certs[i].getCertificate(), true,
					   CertificateOrigin.CERT_ORI_LDAP,
					   CertificateType.CERT_TYPE_END_ENTITY,
					   CertificateTrust.CERT_TRUST_CA_SIGNED,
					   null);
	if (debug) {
	  System.out.println("Updating cert cache with LDAP entry:" + filter);
	}
	certCache.addCertificate(certstatus);
      }
      catch (CertificateChainException e) {
	if (debug) {
	  System.out.println("Found non trusted cert in LDAP directory! "
			     + filter + " - " + e);
	}
      }
      catch (CertificateExpiredException e) {
	// The certificate is trusted but it has expired.
	if (debug) {
	  System.out.println("Certificate in chain has expired. "
			     + filter + " - " + e);
	}
      }
      catch (CertificateNotYetValidException e) {
	// The certificate is trusted but it is not yet valid. Add it to the cache
	// because it may become valid when it is being used.
	if (debug) {
	  System.out.println("Certificate in chain is not yet valid. "
			     + filter + " - " + e);
	}
	certstatus = new CertificateStatus(certs[i].getCertificate(), true,
					   CertificateOrigin.CERT_ORI_LDAP,
					   CertificateType.CERT_TYPE_END_ENTITY,
					   CertificateTrust.CERT_TRUST_CA_SIGNED, null);
	if (debug) {
	  System.out.println("Updating cert cache with LDAP entry:" + filter);
	}
	certCache.addCertificate(certstatus);
      }
    }	
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
      if (certificateFinder != null) {
	Hashtable crl = certificateFinder.getCRL();
	Enumeration enum=crl.keys();
	Certificate certificate=null;
	String alias=null;
	while(enum.hasMoreElements()) {
	  alias=(String)enum.nextElement();
	  certificate=(Certificate)crl.get(alias);
	  CertificateStatus wrapperobject =
	    new CertificateStatus(certificate, false,
				  CertificateOrigin.CERT_ORI_KEYSTORE,
				  CertificateType.CERT_TYPE_END_ENTITY,
				  CertificateTrust.CERT_TRUST_NOT_TRUSTED,
				  null);
	  if (debug) {
	    System.out.println("DirectoryKeyStore.run. Adding CRL for "
			       + alias );
	  }
	  certCache.addCertificate(wrapperobject);
	  //make sure keystore is updated
	  try{
	    deleteEntry(alias);
	    X509Certificate x = (X509Certificate)certificate;
	    //m2.remove(x.getSubjectDN());
	  } catch(Exception e) {
	    e.printStackTrace();
	  }
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
    Vector crllist = null;
    if (certificateFinder != null) {
      Hashtable crl=certificateFinder.getCRL();
      Enumeration enum=crl.keys();
      String alias=null;
      crllist = new Vector();
      while(enum.hasMoreElements()) {
	alias=(String)enum.nextElement();
	// TODO: store CRL in permanent storage
	crllist.addElement(alias);
      }
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
    PrivateKey privatekey = (PrivateKey) keystore.getKey(alias, param.keystorePassword);
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
	// The reply contains a certificate chain and it is valid
	CertificateStatus certstatus =
	  new CertificateStatus(certificateForImport[0], true,
				CertificateOrigin.CERT_ORI_KEYSTORE,
				CertificateType.CERT_TYPE_END_ENTITY,
				CertificateTrust.CERT_TRUST_CA_SIGNED, alias);
	if (debug) {
	  System.out.println("Update cert status in hash map");
	}
	certCache.addCertificate(certstatus);
	certCache.addPrivateKey(privatekey, certstatus);
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
      keystore.setKeyEntry(alias, privatekey, param.keystorePassword,
			   certificateForImport);
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
      FileOutputStream out = new FileOutputStream(param.keystorePath);
      keystore.store(out, param.keystorePassword);
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
    return checkCertificateTrust(certificateReply);
  }

  public Certificate[] checkCertificateTrust(Certificate certificate)
    throws CertificateChainException, CertificateExpiredException,
	   CertificateNotYetValidException
  {

    // Prepare a vector that will contain at least the entity certificate
    // and the signer.
    Vector vector = new Vector(2);
    boolean ok = buildChain((X509Certificate)certificate, vector);
    Certificate acertificate[] = new Certificate[vector.size()];
    if (ok) {
      int i = 0;
      for(int j = vector.size() - 1; j >= 0; j--) {
	acertificate[i] = (Certificate)vector.elementAt(j);
	// Check certificate validity
	((X509Certificate) acertificate[i]).checkValidity();
	i++;
      }
      return acertificate;
    } else {
      // Figure out cause.
      CertificateTrust cause = CertificateTrust.CERT_TRUST_UNKNOWN;
      Principal principal = ((X509Certificate)certificate).getSubjectDN();
      Principal principal1 = ((X509Certificate)certificate).getIssuerDN();
      if(principal.equals(principal1)) {
	// Self signed certificate
	cause = CertificateTrust.CERT_TRUST_SELF_SIGNED;
      }
      throw new CertificateChainException("Failed to establish chain from reply", cause);
    }
  }

  private void initCertCache()
  {
    certCache = new CertificateCache(this);

    try {
      if(keystore.size() > 0) {
	// Build a hash table that indexes keys in the keystore by DN
	if (debug) {
	  System.out.println("++++++ Initializing Certificate Cache");
	}
	initCertCacheFromKeystore(keystore, param.keystorePassword,
				  CertificateType.CERT_TYPE_END_ENTITY);
      }
    }
    catch (KeyStoreException e) {
      if (debug) {
	System.out.println("Unable to access keystore: " + e);
      }
    }

    try {
      if(caKeystore != null && caKeystore.size() > 0) {
	if (debug) {
	  System.out.println("++++++ Initializing CA Certificate Cache");
	}
	// Build a hash table that indexes keys in the CA keystore by DN
	initCertCacheFromKeystore(caKeystore, param.caKeystorePassword,
				  CertificateType.CERT_TYPE_CA);
      }
    }
    catch (KeyStoreException e) {
      if (debug) {
	System.out.println("Unable to access CA keystore: " + e);
      }
    }

    /* Now, all certificates have been cached, but their trust has not
     * been determined yet. This is what we do now.
     * - All certificates in the CA keystore are assumed to be trusted.
     * - For each certificate in the keystore, we verify that it has been
     *   signed by a CA. That is, we need to establish a certificate
     *   chain before granting the trust.
     */
    Enumeration e = certCache.getKeysInCache();
    while (e.hasMoreElements()) {
      X500Name name = (X500Name) e.nextElement();

      ArrayList list = certCache.getCertificates(name);
      ListIterator it = list.listIterator();
      if (debug) {
	System.out.println("-- Checking certificates validity for: " + name);
      }
      while (it.hasNext()) {
	CertificateStatus cs = (CertificateStatus) it.next();
	Certificate certificate = cs.getCertificate();

	try {
	  Certificate[] certs = checkCertificateTrust(certificate);
	  // Could establish a certificate chain. Certificate is trusted.
	  // Update Certificate Status.
	  if (debug) {
	    System.out.println("Certificate chain established");
	  }
	  cs.setCertificateTrust(CertificateTrust.CERT_TRUST_CA_SIGNED);
	}
	catch (CertificateChainException exp) {
	  if (debug) {
	    System.out.println("Unable to get certificate chain. Cause= "
			       + exp.cause);
	  }
	  if (exp.cause == CertificateTrust.CERT_TRUST_SELF_SIGNED) {
	    // Maybe we didn't get a reply from the CA the last time
	    // we created the certificate. Send a new PKCS10 request to the CA.
	    cs.setCertificateTrust(CertificateTrust.CERT_TRUST_SELF_SIGNED);
	  }
	}
	catch (CertificateExpiredException exp) {
	  if (debug) {
	    System.out.println("Certificate in chain has expired. "
			       + " - " + exp);
	  }
	}
	catch (CertificateNotYetValidException exp) {
	  if (debug) {
	    System.out.println("Certificate in chain is not yet valid. "
			       + " - " + exp);
	  }
	}
      }
    }

    if (debug) {
      certCache.printCertificateCache();
    }
  }

  /** Build a hashtable containing certificates. Since an entity (user, agent...)
   * may have multiple keys, each entry in the hashtable contains a Vector
   * of all the certificates for that entity. */
  private void initCertCacheFromKeystore(KeyStore aKeystore, char[] password,
					 CertificateType certType)
    throws KeyStoreException
  {
    for(Enumeration enumeration = aKeystore.aliases(); enumeration.hasMoreElements(); ) {
      String s = (String)enumeration.nextElement();
      Certificate certificate = aKeystore.getCertificate(s);
      CertificateStatus certstatus = null;
      CertificateTrust trust = CertificateTrust.CERT_TRUST_UNKNOWN;

      if(certificate != null) {
	if (certType == CertificateType.CERT_TYPE_CA) {
	  // The certificate is trusted by definition
	  trust = CertificateTrust.CERT_TRUST_CA_CERT;
	}
	certstatus =
	  new CertificateStatus(certificate, true,
				CertificateOrigin.CERT_ORI_KEYSTORE,
				certType,
				trust, s);
	// Update certificate cache
	certCache.addCertificate(certstatus);

	// Update private key cache
	try {
	  PrivateKey key = (PrivateKey) aKeystore.getKey(s, password);
	  if (key != null) {
	    certCache.addPrivateKey(key, certstatus);
	  }	
	}
	catch (Exception e) {
	}
      }
    }
  }

  /** */
  private Certificate[] validateReply(String alias, Certificate certificate,
				      Certificate certificateReply[])
    throws CertificateException
  {
    java.security.PublicKey publickey = certificate.getPublicKey();
    int i;
    
    for(i = 0; i < certificateReply.length; i++) {
      if(publickey.equals(certificateReply[i].getPublicKey())) {
	break;
      }
    }

    if(i == certificateReply.length) {
      throw new CertificateException("Certificate reply does not contain public key for <"
				     + alias + ">");
    }

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


  /** Build a certificate chain.
   *  On output, vector contains an array of certificates leading to
   *  a trusted Certificate Authority, starting with the certificate itself.
   *  Returns true if we could build a chain.
   *  If any 
   */
  private boolean buildChain(X509Certificate x509certificate, Vector vector)
  {
    boolean ret = internalBuildChain(x509certificate, vector, false);
    if (debug) {
      System.out.println("Certificate trust=" + ret);
    }
    return ret;
  }

  /** Check whether at least one of the certificate in the certificate chain
   * is a trusted CA. The certificate chain must have previously been built with
   * checkCertificateTrust(). */
  private boolean internalBuildChain(X509Certificate x509certificate, Vector vector,
				     boolean signedByAtLeastOneCA)
  {
    Principal principal = x509certificate.getSubjectDN();
    Principal principal1 = x509certificate.getIssuerDN();
    if (debug) {
      System.out.println("Build chain: " + principal.getName());
    }

    ArrayList list1 = certCache.getCertificates(principal1.getName());

    if(principal.equals(principal1)) {
      // Self-signed certificate
      vector.addElement(x509certificate);
      CertificateStatus cs = (CertificateStatus) list1.get(0);

      if (cs != null && cs.getCertificateType() == CertificateType.CERT_TYPE_CA) {
	// This is a trusted certificate authority.
	signedByAtLeastOneCA = true;
      }
      if (debug) {
	System.out.println("Certificate is self issued");
      }
      if (param.standalone) {
	// If DirectoryKeyStore is used in the context of a Certificate
	// Authority, then a self-signed certificate is OK.
	return true;
      }
      else {
	return signedByAtLeastOneCA;
      }
    }

    //Vector vector1 = (Vector)hashtable.get(principal1);
    if(list1 == null) {
      if (debug) {
	System.out.println("No Signer certificate in cache");
      }
      // One intermediate CA may not be in the local keystore.
      // We need to go to the LDAP server to get the key if we haven't found
      // a trusted CA yet.
      if (!signedByAtLeastOneCA) {
	if (debug) {
	  System.out.println("Looking up certificate in directory service");
	}
	String filter = parseDN(principal1.toString());
	lookupCertInLDAP(filter);

	// Now, seach again.
	list1 = certCache.getCertificates(principal1.getName());
	if (list1 == null) {
	  // It's OK not to have the full chain if at least one certificate in the
	  // chain is trusted.
	  return signedByAtLeastOneCA;
	}
      }
      else {
	// It's OK not to have the full chain if at least one certificate in the
	// chain is trusted.
	return signedByAtLeastOneCA;
      }
    }

    //Enumeration enumeration = vector1.elements();
    Iterator it = list1.listIterator();
    // Loop through all the issuer keys
    while(it.hasNext()) {
      CertificateStatus cs = (CertificateStatus) it.next();
      X509Certificate x509certificate1 = (X509Certificate)cs.getCertificate();
      java.security.PublicKey publickey = x509certificate1.getPublicKey();
      try {
	x509certificate.verify(publickey);
      }
      catch(Exception exception) {
	if (debug) {
	  System.out.println("Unable to verify signature: "
			     + exception + " - "
			     + x509certificate1.getSubjectDN().toString());
	  exception.printStackTrace();
	}
	continue;
      }

      if (cs.getCertificateType() == CertificateType.CERT_TYPE_CA) {
	// The signing certificate is a CA. Therefore the certificate
	// can be trusted.
	signedByAtLeastOneCA = true;
      }

      if (debug) {
	System.out.println("Found acceptable signing key: "
			   + x509certificate1.getSubjectDN().toString());
      }

      // Recursively build a certificate chain.
      if(internalBuildChain(x509certificate1, vector, signedByAtLeastOneCA)) {
	vector.addElement(x509certificate);
	return true;
      }
    }
    if (debug) {
      System.out.println("No valid signer key");
    }
    //return false;
    return signedByAtLeastOneCA;
  }

  private class BuildChainInfo
  {
    boolean signedByAtLeastOneCA;
    boolean chainValid;
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
    PrivateKey signerPrivateKey = (PrivateKey) keystore.getKey(signerAlias,
							       param.keystorePassword);
    X509Certificate cert = (X509Certificate)keystore.getCertificate(signerAlias);

    //Signature signerSignature = Signature.getInstance(signerPrivateKey.getAlgorithm());
    // TODO: find signature algorithm that works with most crypto providers
    Signature signerSignature = Signature.getInstance("SHA1withRSA");
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

    String reply = CertificateUtility.base64encode(request.getEncoded(),
						   CertificateUtility.PKCS10HEADER,
						   CertificateUtility.PKCS10TRAILER);

    if (debug) {
      System.out.println("generateSigningCertificateRequest:\n" + reply);
    }
    return reply;
  }

  /** Get a list of all the certificates in the keystore */
  private Key[] getCertificates()
  {
    // Get the certificates from the keystore
    Key [] k1 = getCertificates(keystore);

    // Get the certificates from the CA keystore
    Key [] k2 = getCertificates(caKeystore);

    Key [] k = new Key[k1.length + k2.length];
    System.arraycopy(k1, 0, k, 0, k1.length);
    System.arraycopy(k2, 0, k, k1.length, k2.length);
    return k;
  }

  /** Get a list of all the certificates in the keystore */
  private Key[] getCertificates(KeyStore ks)
  {
    if (ks == null) {
      return new Key[0];
    }
    Enumeration en = null;
    try {
      en = ks.aliases();
    }
    catch (KeyStoreException e) {
      System.out.println("Unable to get list of aliases in keystore");
      return null;
    }

    ArrayList certificateList = new ArrayList();

    while(en.hasMoreElements()) {
      String alias = (String)en.nextElement();
      try {
	Certificate c = ks.getCertificate(alias);
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

  /** Add a key pair to the key ring.
   * 1) If needed, a new key pair is generated and stored in the keystore.
   * 2a) If the key being generated is for the node, the a PKCS#10 request
   *     is sent to the Certificate Authority. If the CA replies by signing
   *     the node's certificate, the certificate is installed in the keystore.
   * 2b) If the key being generated is an agent key, then the node acts as a
   *     CA for the agent: the node signs the agent's certificate and also
   *     sends the certificate to the node's CA.
   *     If necessary, a node's key is recursively created for the node.
   *
   * If the keyAlias parameter is null, then it is assumed that no key exists
   * yet in the keystore. In that case, a new key is generated.
   * If alias is not null, an existing key is used. In that case, we first
   * lookup the LDAP directory. The CA may have already signed and published
   * the certificate, in which case it is not necessary to re-generated and
   * send a PKCS#10 request to the CA.
   */
  protected synchronized PrivateKey addKeyPair(String commonName, String keyAlias)
  {
    String request = "";
    String reply = "";

    if (debug) {
      System.out.println("Creating key pair for " + commonName);
    }
    //is node?
    String nodeName = NodeInfo.getNodeName();
    if (nodeName == null && debug) {
      System.out.println("DirectoryKeyStore Error: Cannot get node name");
      return null;
    }
    String alias = null;
    PrivateKey privatekey = null;
    try {
      if(commonName == nodeName){
	// We are node
	if (keyAlias != null) {
	  // Do not create key. There is already one in the keystore.
	  alias = keyAlias;
	  if (debug) {
	    System.out.println("Using existing key: " + keyAlias);
	  }
	  // First, go to the CA to see if the CA has already signed the key.
	  // In that case, there is no need to send a PKCS10 request.
	}
	else {
	  if (debug) {
	    System.out.println("Creating key pair for node: " + nodeName);
	  }
	  alias = makeKeyPair(commonName);
	}
	// At this point, the key pair has been added to the keystore, but we don't
	// have the reply from the certificate authority yet.

	// Send the public key to the Certificate Authority (PKCS10)
	request = generateSigningCertificateRequest(keystore.getCertificate(alias), alias);
	if (debug) {
	  System.out.println("Sending PKCS10 request to CA");
	}
	reply = caClient.sendPKCS(request, "PKCS10");
      } else {
	// check if node cert exist
	// Don't lookup in LDAP, the key should be in the local keystore
	X509Certificate nodex509 = (X509Certificate) findCert(nodeName, LOOKUP_KEYSTORE);
	if(nodex509 == null) {
	  //we don't have a node key pair, so make it
	  if (debug) {
	    System.out.println("Recursively creating key pair for node: " + nodeName);
	  }
	  addKeyPair(nodeName, null);
	}
	// The Node key should exist now (we may have just added it
	// recursively).
	nodex509 = (X509Certificate) findCert(nodeName, LOOKUP_KEYSTORE);
	if (nodex509 == null) {
	  // There was a problem during the generation of the node's key.
	  // Stop the procedure.
	  return null;
	}
	if (keyAlias != null) {
	  // Do not create key. There is already one in the keystore.
	  alias = keyAlias;
	  if (debug) {
	    System.out.println("Using existing key: " + keyAlias);
	  }
	}
	else {
	  if (debug) {
	    System.out.println("Creating key pair for agent: " + commonName);
	  }
	  alias = makeKeyPair(commonName);
	}
	// Generate a pkcs10 request, then sign it with node's key
	//String nodeAlias = findAlias(nodeName);
	request = generateSigningCertificateRequest(keystore.getCertificate(alias), alias);
	// Sign PKCS10 request with node key and send agent cert to CA

	reply = caClient.signPKCS(request, nodex509.getSubjectDN().getName());
      }
    } catch (Exception e) {
      if (debug) {
	System.out.println("Unable to create key: " + commonName + " - Reason:" + e);
	e.printStackTrace();
      }
    }
    if (alias != null) {
      try{ 
	installPkcs7Reply(alias, new ByteArrayInputStream(reply.getBytes()));
	privatekey = (PrivateKey) keystore.getKey(alias, param.keystorePassword);
      } catch(Exception e) {
	if (debug) {
	  System.err.println("Error: can't get certificate for " + commonName);
	  e.printStackTrace();
	}
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
    X500Name x500Name = null;
    String a = null;
    Certificate c = null;
    try {
      x500Name = new X500Name(p.getName());
      a = x500Name.getCommonName();
    }
    catch (Exception e) {
      return null;
    }
    //String a = (String) m.get(p);
    if (a == null) {
      return null;
    }
    try {
      c=findCert(a, LOOKUP_KEYSTORE | LOOKUP_LDAP);
    }
    catch (Exception e) {
      e.printStackTrace();
    }
    return c;
  }

  public Certificate findCert(String name) {
    Certificate c = null;
    try {
      c = findCert(name, LOOKUP_KEYSTORE | LOOKUP_LDAP);
    }
    catch (Exception e) {
      e.printStackTrace();
    }
    return c;
  }

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

  /** Return the next available alias for a given name.
   * A keystore cannot have two entries with the same alias. */
  private String getNextAlias(KeyStore keystore, String name)
  {
    String alias = name + "-";
    int nextIndex = 1;
    int ind;
    try {
      Enumeration list = keystore.aliases();

      while (list.hasMoreElements()) {
	//build up the hashMap
	String a = (String)list.nextElement();
	if (a.startsWith(alias)) {
	  //Extract index
	  ind = Integer.valueOf(a.substring(alias.length())).intValue();
	  if (debug) {
	    System.out.println("Alias: " + alias + " - val: " + ind);
	  }
	  if (ind >= nextIndex) {
	    nextIndex = ind + 1;
	  }
	}
      }
    } catch(Exception e) {
      System.out.println(e);
      e.printStackTrace();
    }
    alias = alias + nextIndex;
    if (debug) {
      System.out.println("Next alias for " + name  + " is " + alias);
    }
    return alias;
  }

  public String makeKeyPair(String commonName)
    throws Exception 
  {
    //generate key pair.
    if (debug) {
      System.out.println("makeKeyPair: " + commonName);
    }

    /*
    SecureRandom sr = new SecureRandom();
    byte bytes[] = new byte[10];
    sr.nextBytes(bytes);
    String rdm = toHex(bytes);

    String alias = commonName + "-" + rdm;
    */
    String alias = getNextAlias(keystore, commonName);
    if (debug) {
      System.out.println("Make key pair:" + alias + ", cn=" + commonName
			 + ", ou=" + defaultOrganizationUnit
			 + ",o=" +  defaultOrganization
			 + ",l=" + defaultLocality
			 + ",st=" + defaultState
			 + ",c=" + defaultState);
    }
    X500Name dname = new X500Name(commonName,
				  defaultOrganizationUnit, defaultOrganization,
				  defaultLocality, defaultState, defaultState);
    doGenKeyPair(alias, dname.getName(), defaultKeyAlgName,
		 defaultKeysize, defaultSigAlgName,
		 defaultValidity);
    return alias;
  }

  /** Generate a key pair and a self-signed certificate */
  public void doGenKeyPair(String alias, String dname,
			   String keyAlgName, int keysize, String sigAlgName,
			   long howLong)
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
			 + " key pair and " + "self-signed certificate ("
			 + sigAlgName + ")");
      System.out.println("\tfor: " + x500name + " - alias:" + alias);
    }
    certandkeygen.generate(keysize);
    PrivateKey privatekey = certandkeygen.getPrivateKey();
    X509Certificate ax509certificate[] = new X509Certificate[1];
    ax509certificate[0] = certandkeygen.getSelfCertificate(x500name, howLong);
    setKeyEntry(alias, privatekey, ax509certificate);

    // Add the certificate to the certificate cache. The key cannot be used
    // yet because it has not been signed by the Certificate Authority.
    CertificateStatus certstatus =
      new CertificateStatus(ax509certificate[0], true,
			    CertificateOrigin.CERT_ORI_KEYSTORE,
			    CertificateType.CERT_TYPE_END_ENTITY,
			    CertificateTrust.CERT_TRUST_SELF_SIGNED, alias);
    certstatus.setPKCS10Date(new Date());
    certCache.addCertificate(certstatus);
    certCache.addPrivateKey(privatekey, certstatus);
  }
  
  public void checkOrMakeCert(String name){
      //check first
      Certificate c = null;
      try{
        c = findCert(name, LOOKUP_KEYSTORE);
	if(c!=null) {
	  return;
	}
      }
      catch(Exception e){
	System.err.println("Can't locate the certificate for:"+name
			   +"--"+e+".generating new one...");
	e.printStackTrace();
      }
      //we'll have to make one
      addKeyPair(name, null);
  }

  /** Build a search filter for LDAP based on the distinguished name
   */
  private String parseDN(String aDN)
  {
    String filter = "(&";

    StringTokenizer parser = new StringTokenizer(aDN, ",=");
    while(parser.hasMoreElements()) {
      String tok1 = parser.nextToken().trim().toLowerCase();
      String tok2 = parser.nextToken();
      filter = filter + "(" + tok1 + "=" + tok2 + ")";
    }
    filter = filter + ")";
    if (debug) {
      System.out.println("Search filter is " + filter);
    }
    return filter;
  }
}
