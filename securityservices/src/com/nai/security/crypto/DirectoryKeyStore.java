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
import java.net.*;

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
import sun.security.util.ObjectIdentifier;

// Cougaar core infrastructure
import org.cougaar.util.ConfigFinder;

// Cougaar security services
import com.nai.security.certauthority.KeyManagement;
import com.nai.security.policy.*;
import com.nai.security.util.*;
import com.nai.security.crypto.ldap.CertDirectoryServiceClient;
import com.nai.security.crypto.ldap.CertDirectoryServiceFactory;
import com.nai.security.crypto.ldap.LdapEntry;
import com.nai.security.crypto.ldap.CertificateRevocationStatus;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.crypto.*;

public class DirectoryKeyStore
{
  /** This keystore stores the following keys:
   *  - Keys that have been introduced through the automated key pair
   *  generation process.
   *  - (Optional) Keys that have been manually installed during Cougaar
   *  installation
   *  This may include key pairs for a Cougaar entity (user, node, agent, ...)
   *   as well as certificates from other entities.
   */
  private KeyStore keystore = null;

  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;

  /** This keystore stores certificates of trusted certificate authorities. */
  private KeyStore caKeystore = null;

  protected  CertDirectoryServiceClient certificateFinder=null;

  //private boolean debug = false;

  /** A hash map to store the private keys, indexed with common name */
  //private HashMap privateKeysAlias = new HashMap(89);

  /** A hash map to store certificates from keystore, caKeystore and the
      LDAP directory service, indexed by distinguished name */

  protected  CertificateCache certCache = null;

  private CRLCache crlCache=null;


  /** A hash map to quickly find an alias given a common name */
  private HashMap commonName2alias = new HashMap(89);

  /** The role under which this node is running
   */
  String role;
  CryptoClientPolicy cryptoClientPolicy;
  private DirectoryKeyStoreParameters param = null;

  /* Update OIDMap to include IssuingDistribution Point Extension &
   * Certificate Issuer Extension
   */

   static {
    try {

      OIDMap.addAttribute("com.nai.security.crlextension.x509.extensions.IssuingDistributionPointExtension","2.5.29.28","x509.info.extensions.IssuingDistibutionPoint");
      OIDMap.addAttribute("com.nai.security.crlextension.x509.extensions.CertificateIssuerExtension","2.5.29.29","x509.info.extensions.CertificateIssuer");

    }
    catch(CertificateException certexp) {
      System.out.println(" Could not add OID Mapping :"+certexp.getMessage());

    }
  }


  /** Initialize the directory key store */
  public DirectoryKeyStore(DirectoryKeyStoreParameters aParam) {
    param = aParam;

    secprop = (SecurityPropertiesService)
      param.serviceBroker.getService(this,
				     SecurityPropertiesService.class,
				     null);
    // LDAP certificate directory
    certificateFinder =
      CertDirectoryServiceFactory.getCertDirectoryServiceClientInstance(
	param.ldapServerType, param.ldapServerUrl);
    if(certificateFinder == null) {
      if (!param.isCertAuth) {
	System.out.println("Error !  Could  not get certificate finder from factory");
	throw new RuntimeException("Error !  Could  not get certificate finder from factory");
      }
      else {
	System.out.println("INFO: CA does not have a superior");
      }
    }

    try {

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

      if (CryptoDebug.debug) {
	System.out.println("listing keys store");
	listKeyStoreAlias(keystore, param.keystorePath);
	System.out.println("listing CA keys store");
	listKeyStoreAlias(caKeystore, param.caKeystorePath);
      }

      try{
	configParser = (ConfigParserService)
	  param.serviceBroker.getService(this,
					 ConfigParserService.class,
					 null);

	cryptoClientPolicy = configParser.getCryptoClientPolicy();
      } catch(Exception e) {
	System.out.println("Error: can't start CA client--"+e.getMessage());
	e.printStackTrace();
      }

      // We running as part of Cougaar, this class may be used to support
      // certificate authority services. In that cases, we need CA policy
      role = secprop.getProperty(secprop.SECURITY_ROLE);
      if (role == null && CryptoDebug.debug == true) {
	System.out.println("DirectoryKeystore warning: Role not defined");
      }

      // Initialize certificate cache
      initCertCache();
      if (!param.isCertAuth) {
	initCRLCache();
      }
    }
    catch (Exception e) {
      e.printStackTrace();
    }

    certCache.printbigIntCache();
  }

  public Enumeration getAliasList()
  {
    Enumeration alias;
    try {
      alias =keystore.aliases();
    }
    catch (Exception exp) {
      exp.printStackTrace();
      return null;
    }
    return alias;

  }
  public String getCommonName(String alias)
  {
    String cn=null;
    try {
      X509Certificate cert=(X509Certificate)keystore.getCertificate(alias);
      cn=getCommonName(cert);
    }
    catch (Exception exp) {
      exp.printStackTrace();
      cn=null;
    }
    return cn;

  }

  /** Dump all the key aliases in a keystore */
  private void listKeyStoreAlias(KeyStore ks, String path) {
    if (ks == null) {
      if (CryptoDebug.debug) {
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
    }
    catch(Exception e) {
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

  public synchronized PrivateKey findPrivateKey(X500Name x500Name) {
    PrivateKey pk = null;
    pk = certCache. getPrivateKey(x500Name);
    return pk;
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

    if (pk != null && CryptoDebug.debug) {
      System.out.println("Found private key in hash map");
    }

    if (pk == null) {
      // Key was not found in keystore either.
      if (CryptoDebug.debug) {
	System.out.println("No private key for " + commonName
			   + " was found in keystore, generating...");
      }
      if (!param.isCertAuth) {
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
  public synchronized X509Certificate findCert(String commonName,
					   int lookupType)
  throws Exception
  {

    X509Certificate cert = null;

    if (CryptoDebug.debug) {
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
    if (CryptoDebug.debug) {
      System.out.println("Search key in local hash table:" + commonName);
    }
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
    if (CryptoDebug.debug) {
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
    if(CryptoDebug.debug)
      System.out.println(" lookupCertInLDAP of Directory keystore called :");
    LdapEntry[] certs = null;
    CertificateStatus certstatus=null;
    // Look in certificate directory service
    if (CryptoDebug.debug) {
      System.out.println("DirectoryKeyStore.findCert. Looking up ["
			 + filter + " ] in LDAP");
    }
    if (certificateFinder != null) {
      certs = certificateFinder.searchWithFilter(filter);
    }
    else {
      System.out.println("WARNING !  certificate finder is null:");

    }
    if(certs==null) {
      System.out.println("Error! search for certs is null in lookupCertInLDAP:");
      return;
    }
    else {
      if (certs.length == 0) {
	if (CryptoDebug.debug) {
	  System.err.println("Failed to get Certificate for " + filter);
	}
      }
    }

    for (int i = 0 ; i < certs.length ; i++) {
      // Since the certificate comes from an LDAP server, it should be trusted
      // (because only a CA should publish certificates to the directory service,
      // but let's check just to make sure. There may be some cases where
      // a particular CA is not trusted locally.
      try {

	X509Certificate[] certChain = checkCertificateTrust(certs[i].getCertificate());
	if(certs[i].getStatus().equals(CertificateRevocationStatus.REVOKED)) {
	  certstatus = new CertificateStatus(certs[i].getCertificate(),false,
					     CertificateOrigin.CERT_ORI_LDAP,
					     certs[i].getCertificateType(),
					     CertificateTrust.CERT_TRUST_REVOKED_CERT,
					     null);
	  // certstatus.setValidity(false);
	}
	else {
	  certstatus = new CertificateStatus(certs[i].getCertificate(), true,
					     CertificateOrigin.CERT_ORI_LDAP,
					     certs[i].getCertificateType(),
					     CertificateTrust.CERT_TRUST_CA_SIGNED,
					     null);
	}
	if (CryptoDebug.debug) {
	  System.out.println("Updating cert cache with LDAP entry:" + filter);
	}
	certCache.addCertificate(certstatus);
	if(certs[i].getCertificateType().equals(CertificateType.CERT_TYPE_CA)) {
	  if(CryptoDebug.debug) {
	    System.out.println("Certificate type is CA certificate  ++++");
	    System.out.println(" Updating CRLCache  with CA entry ");
	  }
	  crlCache.add(((X509Certificate)certs[i].getCertificate()).getSubjectDN().getName());

	}
      }
      catch (CertificateChainException e) {
	if (CryptoDebug.debug) {
	  System.out.println("Found non trusted cert in LDAP directory! "
			     + filter + " - " + e);
	}
      }
      catch (CertificateExpiredException e) {
	// The certificate is trusted but it has expired.
	if (CryptoDebug.debug) {
	  System.out.println("Certificate in chain has expired. "
			     + filter + " - " + e);
	}
      }
      catch (CertificateNotYetValidException e) {
	// The certificate is trusted but it is not yet valid. Add it to the cache
	// because it may become valid when it is being used.
	if (CryptoDebug.debug) {
	  System.out.println("Certificate in chain is not yet valid. "
			     + filter + " - " + e);
	}
	certstatus = new CertificateStatus(certs[i].getCertificate(), true,
					   CertificateOrigin.CERT_ORI_LDAP,
					   certs[i].getCertificateType(),
					   CertificateTrust.CERT_TRUST_CA_SIGNED, null);
	if (CryptoDebug.debug) {
	  System.out.println("Updating cert cache with LDAP entry:" + filter);
	}
	certCache.addCertificate(certstatus);
      }
      catch (CertificateRevokedException certrevoked) {
	if (CryptoDebug.debug) {
	  System.out.println("Found cert in LDAP directory which has been revoked ! "
			     + filter + " - " + certrevoked);
	}
      }
    }
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

    if (CryptoDebug.debug) {
      System.out.println("installPkcs7Reply for " + alias);
    }
    CertificateFactory cf = CertificateFactory.getInstance("X509");

    Collection collection = cf.generateCertificates(inputstream);
    if(collection.isEmpty()) {
      throw new CertificateException("Reply has no certificate");
    }
    if (CryptoDebug.debug) {
      Iterator it = collection.iterator();
      for (int i = 0 ; it.hasNext() ; i++) {
	Object cert = it.next();
	System.out.println("Reply[" + i + "] - " + cert.getClass().getName());
	System.out.println( ((X509Certificate)cert).toString());
      }
    }
    X509Certificate certificateReply[] = new X509Certificate[0];
    certificateReply =
      (X509Certificate[])collection.toArray(certificateReply);

    installCertificate(alias, certificateReply);
  }

  public void setKeyEntry(PrivateKey key, X509Certificate cert) {
     if (CryptoDebug.debug) {
      System.out.println("setKeyEntry for " + cert.toString());
    }
     X509Certificate[] certificateChain = null;
    try {
      certificateChain = checkCertificateTrust(cert);
    }
    catch (Exception e) {
      if (CryptoDebug.debug) {
	System.out.println("Unable to setKeyEntry: " + e);
      }
    }
    if (certificateChain != null) {
      X500Name dname = null;
      try {
	dname = new X500Name(cert.getSubjectDN().getName());
	String commonName = dname.getCommonName();
	String alias = getNextAlias(keystore, commonName);
	setKeyEntry(alias, key, certificateChain);
      }
      catch (Exception e) {
	if (CryptoDebug.debug) {
	  System.out.println("Unable to setKeyEntry: " + e);
	}
      }
    }
  }

  public void installCertificate(String alias,
				 X509Certificate[] certificateChain)
    throws CertificateException, KeyStoreException,
    NoSuchAlgorithmException, UnrecoverableKeyException
  {
    X509Certificate certificateForImport[];

    X509Certificate certificate =
      (X509Certificate)keystore.getCertificate(alias);
    PrivateKey privatekey = (PrivateKey)
      keystore.getKey(alias, param.keystorePassword);

    if(certificate == null) {
      throw new CertificateException(alias + " has no certificate");
    }

    if(certificateChain.length == 1) {
      // There is no certificate chain.
      // We have to construct the chain first.
      if(CryptoDebug.debug)
	System.out.println("Certificate for alias :"+ alias
			   +"does not contain chain");
      certificateForImport = establishCertChain(certificate,
						certificateChain[0]);
      if(CryptoDebug.debug)
	System.out.println(" successfullly established chain");
    }
    else {
      // The PKCS7 reply contains the certificate chain.
      // Validate the chain before proceeding.
      certificateForImport = validateReply(alias,
					   certificate, certificateChain);
    }
    if(certificateForImport != null) {
	setKeyEntry(alias, privatekey, certificateForImport);
	// The reply contains a certificate chain and it is valid
	CertificateStatus certstatus =
	  new CertificateStatus(certificateForImport[0], true,
				CertificateOrigin.CERT_ORI_KEYSTORE,
				CertificateType.CERT_TYPE_END_ENTITY,
				CertificateTrust.CERT_TRUST_CA_SIGNED, alias);
	if (CryptoDebug.debug) {
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

  private void addCN2alias(String alias, X509Certificate x509)
  {
    String cn = getCommonName(x509);
    if (CryptoDebug.debug) {
      System.out.println("addCN2alias: " + cn + "<->" + alias);
    }
    commonName2alias.put(cn, alias);
  }

  private void removeCN2alias(String cn)
  {
    String alias = (String) commonName2alias.get(cn);
    if (CryptoDebug.debug) {
      System.out.println("removeCN2alias: " + cn + "<->" + alias);
    }
    commonName2alias.remove(cn);
  }

  /** Set a key entry in the keystore */
  private void setKeyEntry(String alias, PrivateKey privatekey,
			   X509Certificate[] certificate)
  {
    if (CryptoDebug.debug) {
      System.out.println("Setting keystore private key entry:" + alias);
    }
    addCN2alias(alias, certificate[0]);
    try {
      keystore.setKeyEntry(alias, privatekey, param.keystorePassword,
			   certificate);
    } catch(Exception e) {
      System.out.println("Unable to set key entry in the keystore - "
			 + e.getMessage());
    }
    // Store key store in permanent storage.
    storeKeyStore();
  }

  private void setCertificateEntry(String alias, X509Certificate aCertificate)
  {
    if (CryptoDebug.debug) {
      System.out.println("Setting keystore certificate entry:" + alias);
    }
    addCN2alias(alias, aCertificate);
    try {
      keystore.setCertificateEntry(alias, aCertificate);
    } catch(Exception e) {
      System.out.println("Unable to set certificate in the keystore - "
			 + e.getMessage());
    }
    // Store key store in permanent storage.
    storeKeyStore();
  }

  public void removeEntry(String commonName)
  {
    if (CryptoDebug.debug) {
      System.out.println("Removing entry from keystore:" + commonName);
    }

    String alias = findAlias(commonName);
    deleteEntry(alias);

    //certCache.deleteCertificate();
    //certCache.deletePrivateKey();

    if (CryptoDebug.debug) {
      certCache.printCertificateCache();
    }

  }

  public void deleteEntry(String alias)
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
    if (CryptoDebug.debug) {
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

  /** @param certificate      Contains the self-signed certificate
   *  @param certificateReply Contains the certificate signed by the CA
   */
  private X509Certificate[] establishCertChain(X509Certificate certificate,
					       X509Certificate certificateReply)
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

  public X509Certificate[] checkCertificateTrust(X509Certificate certificate)
    throws CertificateChainException, CertificateExpiredException,
	   CertificateNotYetValidException, CertificateRevokedException
  {

    // Prepare a vector that will contain at least the entity certificate
    // and the signer.
    Vector vector = new Vector(2);
    boolean ok = buildChain(certificate, vector);
    X509Certificate acertificate[] = new X509Certificate[vector.size()];
    if (ok) {
      int i = 0;
      for(int j = vector.size() - 1; j >= 0; j--) {
	acertificate[i] = (X509Certificate)vector.elementAt(j);
	// Check certificate validity
	((X509Certificate) acertificate[i]).checkValidity();
	i++;
      }
      return acertificate;
    } else {
      // Figure out cause.
      CertificateTrust cause = CertificateTrust.CERT_TRUST_UNKNOWN;
      Principal principal = certificate.getSubjectDN();
      Principal principal1 = certificate.getIssuerDN();
      if(principal.equals(principal1)) {
	// Self signed certificate
	cause = CertificateTrust.CERT_TRUST_SELF_SIGNED;
      }
      throw new CertificateChainException("Failed to establish chain from reply", cause);
    }
  }

   private void initCRLCache()
  {
    crlCache=new CRLCache(this);
    try {
      if(caKeystore != null && caKeystore.size() > 0) {
	if (CryptoDebug.debug) {
	  System.out.println("++++++ Initializing CRL Cache");
	}
	// Build a hash table that indexes keys in the CA keystore by DN
	initCRLCacheFromKeystore(caKeystore, param.caKeystorePassword);
      }
    }
    catch (KeyStoreException e) {
      if (CryptoDebug.debug) {
	System.out.println("Unable to access CA keystore: " + e);
      }
    }
  }

  private void initCertCache()
  {
    certCache = new CertificateCache(this);

    try {
      if(keystore.size() > 0) {
	// Build a hash table that indexes keys in the keystore by DN
	if (CryptoDebug.debug) {
	  System.out.println("++++++ Initializing Certificate Cache");
	}
	initCertCacheFromKeystore(keystore, param.keystorePassword,
				  CertificateType.CERT_TYPE_END_ENTITY);
      }
    }
    catch (KeyStoreException e) {
      if (CryptoDebug.debug) {
	System.out.println("Unable to access keystore: " + e);
      }
    }

    try {
      if(caKeystore != null && caKeystore.size() > 0) {
	if (CryptoDebug.debug) {
	  System.out.println("++++++ Initializing CA Certificate Cache");
	}
	// Build a hash table that indexes keys in the CA keystore by DN
	initCertCacheFromKeystore(caKeystore, param.caKeystorePassword,
				  CertificateType.CERT_TYPE_CA);
      }
    }
    catch (KeyStoreException e) {
      if (CryptoDebug.debug) {
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
      if (CryptoDebug.debug) {
	System.out.println("-- Checking certificates validity for: " + name);
      }
      while (it.hasNext()) {
	CertificateStatus cs = (CertificateStatus) it.next();
	X509Certificate certificate = cs.getCertificate();

	try {
	  X509Certificate[] certs = checkCertificateTrust(certificate);
	  // Could establish a certificate chain. Certificate is trusted.
	  // Update Certificate Status.
	  if (CryptoDebug.debug) {
	    System.out.println("Certificate chain established");
	  }
	  cs.setCertificateTrust(CertificateTrust.CERT_TRUST_CA_SIGNED);
	}
	catch (CertificateChainException exp) {
	  if (CryptoDebug.debug) {
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
	  if (CryptoDebug.debug) {
	    System.out.println("Certificate in chain has expired. "
			       + " - " + exp);
	  }
	}
	catch (CertificateNotYetValidException exp) {
	  if (CryptoDebug.debug) {
	    System.out.println("Certificate in chain is not yet valid. "
			       + " - " + exp);
	  }
	}
	catch(CertificateRevokedException certrevoked) {
	  if(CryptoDebug.debug) {
	    System.out.println(" certificate is revoked for dn ="+((X509Certificate)certificate).getSubjectDN().getName());
	    certrevoked.printStackTrace();
	  }

	}
      }
    }

    if (CryptoDebug.debug) {
      certCache.printCertificateCache();
    }
  }

 private void initCRLCacheFromKeystore(KeyStore aKeystore, char[] password)
    throws KeyStoreException
  {
    String s=null;
    X509Certificate certificate=null;
    String dnname=null;
    for(Enumeration enumeration = aKeystore.aliases(); enumeration.hasMoreElements(); ) {
      s = (String)enumeration.nextElement();
      certificate =(X509Certificate) aKeystore.getCertificate(s);
      dnname=certificate.getSubjectDN().getName();
      crlCache.add(dnname);
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
      String s = (String) enumeration.nextElement();
      X509Certificate certificate =
	(X509Certificate) aKeystore.getCertificate(s);
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
  private X509Certificate[] validateReply(String alias,
					  X509Certificate certificate,
					  X509Certificate certificateReply[])
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

    X509Certificate certificate1 = certificateReply[0];
    certificateReply[0] = certificateReply[i];
    certificateReply[i] = certificate1;
    Principal principal = certificateReply[0].getIssuerDN();
    for(int j = 1; j < certificateReply.length - 1; j++) {
      int l;
      for(l = j; l < certificateReply.length; l++) {
	Principal principal1 = certificateReply[l].getSubjectDN();
	if(!principal1.equals(principal))
	  continue;
	X509Certificate certificate2 = certificateReply[j];
	certificateReply[j] = certificateReply[l];
	certificateReply[l] = certificate2;
	principal = certificateReply[j].getIssuerDN();
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
    if (CryptoDebug.debug) {
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
    if (CryptoDebug.debug) {
      System.out.println("Build chain: " + principal.getName());
    }

    ArrayList list1 = certCache.getCertificates(principal1.getName());

    if(principal.equals(principal1)) {
      // Self-signed certificate
      vector.addElement(x509certificate);
      CertificateStatus cs = (CertificateStatus)list1.get(0);
      //  ((list1 == null) ? null : list1.get(0));

      if (cs != null && cs.getCertificateType() == CertificateType.CERT_TYPE_CA) {
	// This is a trusted certificate authority.
	signedByAtLeastOneCA = true;
      }
      if (CryptoDebug.debug) {
	System.out.println("Certificate is self issued");
      }
      if (param.isCertAuth) {
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
      if (CryptoDebug.debug) {
	System.out.println("No Signer certificate in cache");
      }
      // One intermediate CA may not be in the local keystore.
      // We need to go to the LDAP server to get the key if we haven't found
      // a trusted CA yet.
      if (!signedByAtLeastOneCA) {
	if (CryptoDebug.debug) {
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
	if (CryptoDebug.debug) {
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

      if (CryptoDebug.debug) {
	System.out.println("Found acceptable signing key: "
			   + x509certificate1.getSubjectDN().toString());
      }

      // Recursively build a certificate chain.
      if(internalBuildChain(x509certificate1, vector, signedByAtLeastOneCA)) {
	vector.addElement(x509certificate);
	return true;
      }
    }
    if (CryptoDebug.debug) {
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
  public String generateSigningCertificateRequest(X509Certificate certificate,
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
      if (CryptoDebug.debug) {
	System.out.println("Signing certificate request with alias="
			   + signerAlias);
      }
      request.encodeAndSign(x500signer);
    }
    catch (CertificateException e) {
      System.out.println("Unable to sign certificate request." + e);
    }

    String reply = CertificateUtility.base64encode(request.getEncoded(),
						   CertificateUtility.PKCS10HEADER,
						   CertificateUtility.PKCS10TRAILER);

    /*
    if (debug) {
      System.out.println("GenerateSigningCertificateRequest:\n" + reply);
    }
    */
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
	X509Certificate c = (X509Certificate)ks.getCertificate(alias);
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

  protected synchronized PrivateKey addKeyPair(String commonName,
					       String keyAlias)
  {

    String dn = "cn=" + commonName
      + ", ou=" + cryptoClientPolicy.getCertificateAttributesPolicy().ou
      + ",o=" + cryptoClientPolicy.getCertificateAttributesPolicy().o
      + ",l=" + cryptoClientPolicy.getCertificateAttributesPolicy().l
      + ",st=" + cryptoClientPolicy.getCertificateAttributesPolicy().st
      + ",c=" + cryptoClientPolicy.getCertificateAttributesPolicy().c;
    //    + "," + cryptoClientPolicy.getCertificateAttributesPolicy().domain;
    X500Name dname = null;
    try {
      dname = new X500Name(dn);
    }
    catch (IOException e) {
      System.out.println("Unable to add key pair for " + commonName);
      return null;
    }
    return addKeyPair(dname, keyAlias);
  }

  /**
   * Add a key pair to the key ring.
   * If needed, a new key pair is generated and stored in the keystore.
   * If the key being generated is for the node, the a PKCS#10 request
   * is sent to the Certificate Authority. If the CA replies by signing
   * the node's certificate, the certificate is installed in the keystore.
   * If the key being generated is an agent key, then the node acts as a
   * CA for the agent: the node signs the agent's certificate and also
   * sends the certificate to the node's CA.
   * If necessary, a node's key is recursively created for the node.
   *
   * If the keyAlias parameter is null, then it is assumed that no key exists
   * yet in the keystore. In that case, a new key is generated.
   * If alias is not null, an existing key is used. In that case, we first
   * lookup the LDAP directory. The CA may have already signed and published
   * the certificate, in which case it is not necessary to re-generated and
   * send a PKCS#10 request to the CA.
   *
   * @param commonName - the common name of the entity (agent or node)
   * @param keyAlias - the alias of the key in the keystore
   * @return - the private key of the entity
   */
  protected synchronized PrivateKey addKeyPair(X500Name dname,
					       String keyAlias)
  {
    String request = "";
    String reply = "";

    //is node?
    String nodeName = NodeInfo.getNodeName();
    String commonName = null;
    try {
      commonName = dname.getCommonName();
    }
    catch (IOException e) {
      System.out.println("Unable to add key pair:" + e);
      return null;
    }

    if (CryptoDebug.debug) {
      System.out.println("Creating key pair for "
			 + dname + " - Node name:" + nodeName
			 + " - Common Name=" + commonName);
    }

    if (nodeName == null && CryptoDebug.debug) {
	System.out.println("DirectoryKeyStore Error: Cannot get node name");
	return null;
    }
    String alias = null;
    PrivateKey privatekey = null;
    try {
      /* If the requested key is for the node, the key is self signed.
       * If the requested key is for an agent, and the node is a signer,
       *  then the agent key is signed by the node.
       * If the node is not a signer, the requested key is self-signed.
       */
      if(commonName.equals(nodeName)
	 || !cryptoClientPolicy.getCertificateAttributesPolicy().nodeIsSigner) {
	// Create a self-signed key and send it to the CA.
	if (keyAlias != null) {
	  // Do not create key. There is already one in the keystore.
	  alias = keyAlias;
	  if (CryptoDebug.debug) {
	    System.out.println("Using existing key: " + keyAlias);
	  }
	  // First, go to the CA to see if the CA has already signed the key.
	  // In that case, there is no need to send a PKCS10 request.
          return getNodeCert(nodeName);
	}
	else {
	  if (CryptoDebug.debug) {
	    System.out.println("Creating key pair for node: " + nodeName);
	  }
	  alias = makeKeyPair(dname);
	}
	// At this point, the key pair has been added to the keystore,
	// but we don't have the reply from the certificate authority yet.
	// Send the public key to the Certificate Authority (PKCS10)
	if (!param.isCertAuth) {
	  request =
	    generateSigningCertificateRequest((X509Certificate)
					      keystore.getCertificate(alias),
					      alias);
	  if (CryptoDebug.debug) {
	    System.out.println("Sending PKCS10 request to CA");
	  }
	  reply = sendPKCS(request, "PKCS10");
	}
	else {
	}
      }
      else {
        if (getNodeCert(nodeName) == null)
          return null;

	// The Node key should exist now
	if (CryptoDebug.debug) {
	  System.out.println("Searching node key again: " + nodeName);
	}
	X509Certificate nodex509 =
	  (X509Certificate) findCert(nodeName, LOOKUP_KEYSTORE);
	if (CryptoDebug.debug) {
	  System.out.println("Node key is: " + nodex509);
	}
	if (nodex509 == null) {
	  // There was a problem during the generation of the node's key.
	  // Stop the procedure.
	  if (CryptoDebug.debug) {
	    System.out.println("Error: Unable to get node's key");
	  }
	  return null;
	}
	if (keyAlias != null) {
	  // Do not create key. There is already one in the keystore.
	  alias = keyAlias;
	  if (CryptoDebug.debug) {
	    System.out.println("Using existing key: " + keyAlias);
	  }
	}
	else {
	  if (CryptoDebug.debug) {
	    System.out.println("Creating key pair for agent: " + dname);
	  }
	  alias = makeKeyPair(dname);
	}
	// Generate a pkcs10 request, then sign it with node's key
	//String nodeAlias = findAlias(nodeName);
	request =
	  generateSigningCertificateRequest((X509Certificate)
					    keystore.getCertificate(alias),
					    alias);
	// Sign PKCS10 request with node key and send agent cert to CA
	reply = signPKCS(request, nodex509.getSubjectDN().getName());
      }
    } catch (Exception e) {
      if (CryptoDebug.debug) {
	System.out.println("Unable to create key: " + dname
			   + " - Reason:" + e);
	e.printStackTrace();
      }
    }

    if (alias != null) {
      privatekey = processPkcs7Reply(alias, reply);
    }
    return privatekey;
  }

  private PrivateKey getNodeCert(String nodeName)
    throws Exception {
    PrivateKey nodeprivatekey = null;
    X509Certificate nodex509 = null;
    String request = "";
    String reply = "";

    // check if node cert exist
    if (CryptoDebug.debug) {
      System.out.println("Searching node key: " + nodeName);
    }

    String nodeAlias = findAlias(nodeName);
    if (nodeAlias != null) {
      nodex509 = findCert(nodeName, LOOKUP_KEYSTORE);
      if(nodex509 == null) {
        // maybe approved and in LDAP?
        nodex509 = findCert(nodeName, LOOKUP_LDAP);
        if (nodex509 != null) {
          // install the certificate into keystore

          X509Certificate certificate = (X509Certificate) keystore.getCertificate(nodeAlias);
          if (certificate == null) {
            throw new CertificateException(nodeAlias + "has no certificate.");
          }
          X509Certificate [] certForImport = establishCertChain(certificate, nodex509);
          if (nodeprivatekey != null)
            setKeyEntry(nodeAlias, nodeprivatekey, certForImport);
        }
      }

      if(nodex509 == null) {
        // Richard -- not in LDAP or local keystore
        // might be still pending or denied
        // check with CA, if nothing found then create new key pair
        // if still pending or denied, return null
        if (CryptoDebug.debug) {
          System.out.println("Node certificate not found, checking pending status.");
        }

        request =
          generateSigningCertificateRequest((X509Certificate)
                                            keystore.getCertificate(nodeAlias),
                                            nodeAlias);
        if (CryptoDebug.debug) {
          System.out.println("Sending PKCS10 request to CA");
        }
        reply = sendPKCS(request, "PKCS10");
        // check status
        String strStat = "status=";
        int statindex = reply.indexOf(strStat);
        if (statindex >= 0) {
          // in the pending mode
          if (CryptoDebug.debug) {
            System.out.println("Certificate in pending mode.");
          }
          statindex += strStat.length();
          int status = Integer.parseInt(reply.substring(statindex,
                                                        statindex + 1));
          if (CryptoDebug.debug) {
            System.out.println("pending status is: "
                               + reply.substring(statindex,
                                                 statindex + 1));
          }
          if (status == KeyManagement.PENDING_STATUS_PENDING) {
            System.out.println("Certificate is pending for approval.");
          }
          else if (status == KeyManagement.PENDING_STATUS_DENIED) {
            System.out.println("Certificate is denied by CA.");
          }
          // else approved, why not certificate in the LDAP?

          return null;
        }
        else {
          // get back the reply right away
          return processPkcs7Reply(nodeAlias, reply);
        }
      }
      nodeprivatekey = (PrivateKey) keystore.getKey(nodeAlias,
						    param.keystorePassword);
    }
    else {

      //we don't have a node key pair, so make it
      if (CryptoDebug.debug) {
        System.out.println("Recursively creating key pair for node: "
                           + nodeName);
      }
      nodeprivatekey = addKeyPair(nodeName, null);
      if (CryptoDebug.debug) {
        System.out.println("Node key created: " + nodeName);
      }
    }
    return nodeprivatekey;
  }

  private PrivateKey processPkcs7Reply(String alias, String reply) {
    PrivateKey privatekey = null;
    // Richard -- check whether pending
    String strStat = "status=";
    int statindex = reply.indexOf(strStat);
    if (statindex >= 0) {
      if (CryptoDebug.debug) {
        System.out.println("processPkcs7Reply: certificate in pending mode. ");
      }
      return null;
    }
    if (reply.length() == 0)
      return null;

    try{
      installPkcs7Reply(alias, new ByteArrayInputStream(reply.getBytes()));
      privatekey = (PrivateKey) keystore.getKey(alias, param.keystorePassword);
    } catch (java.security.cert.CertificateNotYetValidException e) {
      if (CryptoDebug.debug) {
        Date d = new Date();
        System.err.println("Error: Certificate not yet valid for:"
                           + alias
                           + " (" + e + ")"
                           + " Current date is " + d.toString());
        e.printStackTrace();
      }
    } catch(Exception e) {
      if (CryptoDebug.debug) {
        System.err.println("Error: can't get certificate for " + alias);
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

  public X509Certificate findCert(Principal p) {
    X500Name x500Name = null;
    String a = null;
    X509Certificate c = null;
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

  public X509Certificate findCert(String name) {
    X509Certificate c = null;
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
    if (CryptoDebug.debug) {
      Set st = commonName2alias.keySet();
      Iterator it = st.iterator();
      System.out.println("CommonName to Alias Hash map contains:");
      while (it.hasNext()) {
	String cn = (String) it.next();
	System.out.println("cn=" + cn + " <-> " + commonName2alias.get(cn));
      }
    }
  }

  public String findAlias(String commonName) {
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
	  if (CryptoDebug.debug) {
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
    if (CryptoDebug.debug) {
      System.out.println("Next alias for " + name  + " is " + alias);
    }
    return alias;
  }

  public String makeKeyPair(X500Name dname)
    throws Exception
  {
    //generate key pair.
    if (CryptoDebug.debug) {
      System.out.println("makeKeyPair: " + dname);
    }
    String commonName = dname.getCommonName();

    String alias = getNextAlias(keystore, commonName);

    if (CryptoDebug.debug) {
      System.out.println("Make key pair:" + alias + ":" + dname.toString());
    }
    doGenKeyPair(alias,
		 dname,
		 cryptoClientPolicy.getCertificateAttributesPolicy().keyAlgName,
		 cryptoClientPolicy.getCertificateAttributesPolicy().keysize,
		 cryptoClientPolicy.getCertificateAttributesPolicy().sigAlgName,
		 cryptoClientPolicy.getCertificateAttributesPolicy().howLong);
    return alias;
  }

  /** Generate a key pair and a self-signed certificate */
  public void doGenKeyPair(String alias, X500Name dname,
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
    KeyCertGenerator certandkeygen = new KeyCertGenerator(keyAlgName,
							  sigAlgName, null);
    if (CryptoDebug.debug) {
      System.out.println("Generating " + keysize + " bit " + keyAlgName
			 + " key pair and " + "self-signed certificate ("
			 + sigAlgName + ")");
      System.out.println("\tfor: " + dname + " - alias:" + alias);
    }
    certandkeygen.generate(keysize);
    PrivateKey privatekey = certandkeygen.getPrivateKey();
    X509Certificate ax509certificate[] = new X509Certificate[1];
    ax509certificate[0] = certandkeygen.getSelfCertificate(dname, howLong);
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
  
  public void checkOrMakeCert(String commonName) {
    String dn = "cn=" + commonName
      + ", ou=" + cryptoClientPolicy.getCertificateAttributesPolicy().ou
      + ",o=" + cryptoClientPolicy.getCertificateAttributesPolicy().o
      + ",l=" + cryptoClientPolicy.getCertificateAttributesPolicy().l
      + ",st=" + cryptoClientPolicy.getCertificateAttributesPolicy().st
      + ",c=" + cryptoClientPolicy.getCertificateAttributesPolicy().c;
    //    + "," + cryptoClientPolicy.getCertificateAttributesPolicy().domain;

    try {
      X500Name dname = new X500Name(dn);
      checkOrMakeCert(dname);
    }
    catch (IOException e) {
      System.out.println("Unable to add key pair:" + e);
    }
  }

  public void checkOrMakeCert(X500Name dname) {
    if (CryptoDebug.debug) {
      System.out.println("CheckOrMakeCert: " + dname.toString());
    }
    //check first
    X509Certificate c = null;
    try{
      c = findCert(dname.getCommonName(), LOOKUP_KEYSTORE);
      if(c!=null) {
	return;
      }
    }
    catch(Exception e){
      System.err.println("Can't locate the certificate for:"
			 + dname.toString()
			 +"--"+e+".generating new one...");
      e.printStackTrace();
    }
    if (CryptoDebug.debug) {
      System.out.println("checkOrMakeCert: creating key for "
			 + dname.toString());
    }
    //we'll have to make one
    addKeyPair(dname, null);
  }

   public void setSleeptime(long sleeptime)
  {
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("writeCrlparam"));
    }
    crlCache.setSleepTime(sleeptime);
    //sleep_time=sleeptime;
  }

  public long  getSleeptime()
  {
    return  crlCache.getSleepTime();
  }

  /** Build a search filter for LDAP based on the distinguished name
   */
  public  String parseDN(String aDN)
  {
    String filter = "(&";

    StringTokenizer parser = new StringTokenizer(aDN, ",=");
    while(parser.hasMoreElements()) {
      String tok1 = parser.nextToken().trim().toLowerCase();
      String tok2 = parser.nextToken();
      filter = filter + "(" + tok1 + "=" + tok2 + ")";
    }
    filter = filter + ")";
    if (CryptoDebug.debug) {
      System.out.println("Search filter is " + filter);
    }
    return filter;
  }

  /**
   * Extract a private key/certificate pair from the keystore.
   * Sign with node key.
   *
   * =============
   * Process for moving agent A key from node X to node Y:
   * 1) The Cougaar system shuts down agent A.
   * 2) The cryptographic service is notified that A has to move
   *    from X to Y.
   * 3) The crypto service extracts agent A's private key and
   *    certificate from the keystore.
   * 4) The crypto service creates a PKCS#12 envelope to wrap the
   *    agent cryptographic material in a secure container that
   *    can be transfered over the network.
   *    The PKCS#12 envelope contains:
   *      - Node's X certificate. This is used by Node Y to verify
   *        that the sender (X) is trusted.
   *        Node's A certificate is in the clear.
   *      - The agent private key and public key, which are both signed
   *        and encrypted. It is signed using X's private key and
   *        encrypted using Y's public key.
   * 5) The Cougaar system sends the PKCS#12 envelope to the receiver Node
   *    using Cougaar messaging mechanism.
   * 6) The receiving Cougaar system notifies its crypto service
   *    that a PKCS#12 message has been received.
   * 7) Receiver node Y installs the key of agent A in its own keystore.
   * 8) Node Y sends an acknowledgement to node X.
   * 9) Nody Y starts agent A.
   * 10) When X receives the acknowledgement, it deletes agent A's
   *     private key from its key store.
   *
   * Steps 3) & 4) are implemented in the getPkcs12Envelope method.
   * Steps 7) is implemented in the installPkcs12Envelope method.
   */
  public byte[] getPkcs12Envelope(String agentCN, String rcvrNode)
  {
    PrivateKeyPKCS12 pkcs12Mgmt = new PrivateKeyPKCS12(this);

    String nodeName = NodeInfo.getNodeName();
    X509Certificate signerCertificate = findCert(nodeName);
    PrivateKey signerPrivKey = findPrivateKey(nodeName);

    X509Certificate cert = findCert(agentCN);
    PrivateKey privKey = findPrivateKey(agentCN);

    X509Certificate rcvrCert = findCert(rcvrNode);
    PrivateKey rcvrPrivKey = findPrivateKey(rcvrNode);

    byte[] pkcs12 = pkcs12Mgmt.protectPrivateKey(privKey,
						 cert,
						 signerPrivKey,
						 signerCertificate,
						 rcvrCert);
    return pkcs12;
  }

  public void installPkcs12Envelope(byte[] pfxBytes)
  {
    PrivateKeyPKCS12 pkcs12Mgmt = new PrivateKeyPKCS12(this);

    String nodeName = NodeInfo.getNodeName();
    X509Certificate rcvrCert = findCert(nodeName);
    PrivateKey rcvrPrivKey = findPrivateKey(nodeName);

    PrivateKeyCert[] pkey = pkcs12Mgmt.getPfx(pfxBytes,
					      rcvrPrivKey,
					      rcvrCert);
    for (int i = 0 ; i < pkey.length ; i++) {
      if (pkey[i] == null) {
	continue;
      }
      CertificateStatus cs = pkey[i].getCertificateStatus();
      PrivateKey pk = pkey[i].getPrivateKey();

      X509Certificate[] certChain = null;
      try {
	certChain = checkCertificateTrust(cs.getCertificate());
      }
      catch (Exception e) {
	if (CryptoDebug.debug) {
	  System.out.println("Warning: Certificate cannot be trusted");
	}
	// Do not add to the list
	continue;
      }

      // Get the common name of that certificate
      String cn = getCommonName(cs.getCertificate());

      // Get the next available alias for this key.
      String alias = getNextAlias(keystore, cn);

      // Set the key entry in the keystore.
      setKeyEntry(alias, pk, certChain);

      // Update the certificate cache
      certCache.addCertificate(cs);

      // Update private key cache
      certCache.addPrivateKey(pk, cs);
    }
  }

  private String sendPKCS(String request, String pkcs) {
    if (!param.isCertAuth) {
      String reply = "";
      try {
	TrustedCaPolicy[] trustedCaPolicy = cryptoClientPolicy.getTrustedCaPolicy();
	if (CryptoDebug.debug) {
	  System.out.println("Sending request to "
			     + trustedCaPolicy[0].caURL
			     + ", DN= "
			     + trustedCaPolicy[0].caDN);
	}
	URL url = new URL(trustedCaPolicy[0].caURL);
	HttpURLConnection huc = (HttpURLConnection)url.openConnection();
	// Let the system know that we want to do output
	huc.setDoOutput(true);
	// Let the system know that we want to do input
	huc.setDoInput(true);
	// No caching, we want the real thing
	huc.setUseCaches(false);
	// Specify the content type
	huc.setRequestProperty("Content-Type",
			       "application/x-www-form-urlencoded");
	huc.setRequestMethod("POST");
	PrintWriter out = new PrintWriter(huc.getOutputStream());
	String content = "pkcs=" + URLEncoder.encode(pkcs);
	content = content + "&role=" + URLEncoder.encode(role);
	content = content + "&dnname="
	  + URLEncoder.encode(trustedCaPolicy[0].caDN);
	content = content + "&pkcsdata=" + URLEncoder.encode(request);
	out.println(content);
	out.flush();
	out.close();

	BufferedReader in =
	  new BufferedReader(new InputStreamReader(huc.getInputStream()));
	int len = 2000;     // Size of a read operation
	char [] cbuf = new char[len];
	while (in.ready()) {
	  int read = in.read(cbuf, 0, len);
	  reply = reply + new String(cbuf, 0, read);
	}
	in.close();
	if (CryptoDebug.debug) {
	  System.out.println("Reply: " + reply);
	}

      } catch(Exception e) {
	System.err.println("Error: sending PKCS request to CA failed--"
			   + e.getMessage());
	e.printStackTrace();
      }
      return reply;
    }
    else {
      return null;
    }
  }

  private String signPKCS(String request, String nodeDN){
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try{
      if (CryptoDebug.debug) {
	System.out.println("Signing PKCS10 request with node");
      }
      CertificateManagementService km = (CertificateManagementService)
	param.serviceBroker.getService(this,
				       CertificateManagementService.class,
				       null);
      km.setParameters(nodeDN);

      X509Certificate[] cf =
	km.processPkcs10Request(new ByteArrayInputStream(request.getBytes()));
      PrintStream ps = new PrintStream(baos);
      CertificateUtility.base64EncodeCertificates(ps, cf);
      //get the output to the CA
      String req = baos.toString();
      String reply = sendPKCS(req, "PKCS7");
    } catch(Exception e) {
      System.err.println("Error: can't get the certificate signed--"
			 + e.getMessage());
      e.printStackTrace();
    }
    return baos.toString();
  }

}
