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

package org.cougaar.core.security.crypto;

import java.io.*;
import java.util.*;
import java.net.*;
import javax.naming.directory.*;
import javax.naming.*;

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
import org.cougaar.core.service.*;
import org.cougaar.core.naming.*;
import org.cougaar.core.mts.*;
import org.cougaar.core.service.LoggingService;

// Cougaar security services
import org.cougaar.core.security.certauthority.KeyManagement;
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.util.*;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.ldap.CertificateRevocationStatus;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;
import org.cougaar.core.security.services.ldap.LdapEntry;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.services.identity.*;
import org.cougaar.core.security.ssl.KeyManager;

import org.cougaar.core.security.test.crypto.*;
import org.cougaar.core.security.dataprotection.*;

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
 
  private SecurityPropertiesService secprop = null;
  private ConfigParserService configParser = null;
  private DirContext namingContext = null;

  /** This keystore stores certificates of trusted certificate authorities. */
  //private KeyStore caKeystore = null;

  protected  CertDirectoryServiceClient certificateFinder=null;
  
  private LoggingService log;

  /** The role under which this node is running
   */
  String role;
  CryptoClientPolicy cryptoClientPolicy;
  private DirectoryKeyStoreParameters param = null;

  private List       _initKeyManager = new LinkedList();
  private boolean    _initializing = true;

  /** Cache for getNamingAttributes
   */
  private Hashtable _namingAttributesCache = new Hashtable();

  /**
   * Cache for CA to store key pair request that is blocked because CA
   * key has not been generated yet. Key will be generated and cache
   * will be cleared after CA key has been generated.
   */
  private Hashtable requestedIdentities = new Hashtable();

  /* Update OIDMap to include IssuingDistribution Point Extension &
   * Certificate Issuer Extension
   */

  static {
    try {
      OIDMap.addAttribute("org.cougaar.core.security.crlextension.x509.extensions.IssuingDistributionPointExtension","2.5.29.28","x509.info.extensions.IssuingDistibutionPoint");
      OIDMap.addAttribute("org.cougaar.core.security.crlextension.x509.extensions.CertificateIssuerExtension","2.5.29.29","x509.info.extensions.CertificateIssuer");

    }
    catch(CertificateException certexp) {
      System.err.println(" Could not add OID Mapping :"+certexp.getMessage());
    }
  }

  public synchronized void setKeyManager(KeyManager km) {
    if (!_initializing) {
      km.finishInitialization();
    } else {
      _initKeyManager.add(km);
    }
  }

  public synchronized void finishInitialization() {
    // LDAP certificate directory
    if (_initializing) {
      _initializing = false;

      Iterator iter = _initKeyManager.iterator();
      while (iter.hasNext()) {
        KeyManager km = (KeyManager) iter.next();
	km.finishInitialization();
      } // end of while (iter.hasNext())
    } // end of if (_initializing)
  }

  /** Initialize the directory key store */
  public DirectoryKeyStore(DirectoryKeyStoreParameters aParam) {
    param = aParam;
    
    secprop = (SecurityPropertiesService)
      param.serviceBroker.getService(this,
				     SecurityPropertiesService.class,
				     null);
    this.log = (LoggingService)
      param.serviceBroker.getService(this,
				     LoggingService.class, null);
    
    try{
      configParser = (ConfigParserService)
	param.serviceBroker.getService(this,
				       ConfigParserService.class,
				       null);
      SecurityPolicy[] sp =
	configParser.getSecurityPolicies(CryptoClientPolicy.class);
      cryptoClientPolicy = (CryptoClientPolicy) sp[0];

    } catch(Exception e) {
      if (log.isErrorEnabled()) {
	log.error("Can't start CA client: "+e.getMessage());
      }
    }

    // We running as part of Cougaar, this class may be used to support
    // certificate authority services. In that cases, we need CA policy
    role = secprop.getProperty(secprop.SECURITY_ROLE);
    if (role == null && log.isWarnEnabled()) {
      log.warn("DirectoryKeystore warning: Role not defined");
    }

    CertDirectoryServiceRequestor cdsr =
      new CertDirectoryServiceRequestorImpl(param.ldapServerUrl, param.ldapServerType,
					    param.serviceBroker, param.defaultCaDn);
    certificateFinder = (CertDirectoryServiceClient)
      param.serviceBroker.getService(cdsr, CertDirectoryServiceClient.class, null);
    if(certificateFinder == null) {
      if (!param.isCertAuth) {
	if (log.isErrorEnabled()) {
	  log.error("Could  not get certificate finder from factory");
	}
	throw new RuntimeException("Could  not get certificate finder from factory");
      } else {
	if (log.isInfoEnabled()) {
	  log.info("CA: LDAP directory service not set yet.");
	}
      }
    }
    setCertificateTrustInCache();
  }

  private void setCertificateTrustInCache() {
     
    
    /* Now, all certificates have been cached, but their trust has not
     * been determined yet. This is what we do now.
     * - All certificates in the CA keystore are assumed to be trusted.
     * - For each certificate in the keystore, we verify that it has been
     *   signed by a CA. That is, we need to establish a certificate
     *   chain before granting the trust.
     */
    Hashtable selfsignedCAs = new Hashtable();
    if (log.isDebugEnabled()) {
      log.debug("Checking certificate trust called ");
    }
    CertificateCacheService cacheservice=(CertificateCacheService)
      param.serviceBroker.getService(this,
				     CertificateCacheService.class,
				     null);
        
    Enumeration e = null;
    if( cacheservice!=null){
      e=cacheservice.getKeysInCache();
    }
    X500Name name = null;
        
    if(e!=null) {
      // Looping through all the keys in the certificate cache.
      while (e.hasMoreElements()) {
	String certdn = (String)e.nextElement();
	try {
	  name = new X500Name(certdn);
	} catch (IOException iox) {
	  if (log.isWarnEnabled()) {
	    log.warn("Cannot init X500Name " + certdn + " in initCertCache: " + e);
	  }
	}
	
	List list = null;
	if(cacheservice!=null) {
	  list=cacheservice.getCertificates(name);
	}
	ListIterator it = list.listIterator();
	if (log.isDebugEnabled()) {
	  log.debug("-- Checking certificates validity for: " + name);
	}
	
	boolean isTrusted = false; // Raise a warning if there is no trusted cert for that entity.
	while (it.hasNext()) {
	  CertificateStatus cs = (CertificateStatus) it.next();
	  X509Certificate certificate = cs.getCertificate();
	  if (setCertificateTrust(certificate, cs, name, selfsignedCAs)) {
	    isTrusted = true;
	  }
	} // END while(it.hasNext())
	if (isTrusted == false) {
	  if (log.isInfoEnabled()) {
	    log.info("No trusted certificate was found for " + name.toString());
	  }
	}
      } // END while(e.hasMoreElements()
    }

    for (Enumeration en = selfsignedCAs.keys(); en.hasMoreElements(); ) {
      try {
	String certdn = (String)en.nextElement();
	try {
	  name = new X500Name(certdn);
	} catch (IOException iox) {
	  if (log.isWarnEnabled()) {
	    log.warn("Cannot init X500Name " + certdn + " in initCertCache: " + e);
	  }
	}
        getNodeCert(name,null);
      } catch (Exception ex) {
        log.warn("Exception in initCertCache.getNodeCert: " + ex.toString());
      }
    }
  }

  private void publishCAToLdap(String caDN) {
    CertificateManagementService km = (CertificateManagementService)
      param.serviceBroker.getService(
	new CertificateManagementServiceClientImpl(caDN),
	CertificateManagementService.class,
	null);
    if (log.isDebugEnabled())
      log.debug("adding CA certificate to LDAP: " + caDN);
  }
   
  public List findPrivateKey(String cougaarName) {
    return findPrivateKey(cougaarName, true);
  }

  /** Lookup a private key given a Cougaar name.
   *  Currently, the Cougaar name is the common name.
   */
  public List findPrivateKey(String cougaarName, boolean validOnly) {
    // getX500DN only works for agent/node/server, does not work for CA and user
    
    CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												 CertificateCacheService.class,
												 null);
    if(cacheservice==null) {
      log.warn(" Unable to get Certificate Cache service in findPrivateKey");
      return null;
    }
    if (param.isCertAuth) {
      List nameList = cacheservice.getX500NameFromNameMapping(cougaarName);
      if (nameList != null && nameList.size()> 0) {
	X500Name dname = (X500Name)nameList.get(0);
	return findPrivateKey(dname, validOnly);
      }
      // else no cert has been created
      return null;
    }
    return findPrivateKey(CertificateUtility.getX500Name( getX500DN(cougaarName)), validOnly);
       
  }

  /** Returns a list of private keys
   * @return A List of PrivateKeyCert
   */
  public List findPrivateKey(X500Name x500Name) {
    return findPrivateKey(x500Name, true);
  }

  public List findPrivateKey(X500Name x500Name, boolean validOnly) {
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("readPrivateKey"));
    }

    if (log.isDebugEnabled()) {
      log.debug("get Private key for " + x500Name + ". ValidOnly=" + validOnly);
    }

      
      
    CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												 CertificateCacheService.class,
												 null);
    if(cacheservice==null) {
      log.error(" Unabale to get Certificate cache service in findPrivateKey:");
    }
      


    // First, try with the hash map (cache)
    List pkc = null;
    if (validOnly) {
      //if(cacheservice!=null){
      pkc = getValidPrivateKeys(x500Name);
      //}
    }
    else {
      if(cacheservice!=null){
	pkc = cacheservice.getPrivateKeys(x500Name);
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("Found " +
		(pkc == null ? 0 : pkc.size()) +
		" private keys for "
		+ x500Name.toString());
    }

    /* Now, we have a private key. However, the key may not be valid for the
     * following reasons:
     *   + the key has expired
     *   + the key was generated, but we couldn't get it signed from the CA
     */
    return pkc;
  }

  /** Lookup a certificate.
   * LOOKUP_LDAP set: Lookup in LDAP directory service.
   * LOOKUP_KEYSTORE: Lookup in keystore file.
   * LOOKUP_FORCE_LDAP_REFRESH: Force a new lookup in the LDAP service.
   * LOOKUP_SSL: Lookup certificates retrieved during an SSL handshake.
   * @return A list of CertificateStatus
   */
  public List findCert(String commonName,
		       int lookupType)
    {
      return findCert(commonName, lookupType, true);
    }

  public List findCert(String commonName,
		       int lookupType, boolean validOnly)
    {
      // getX500DN only works for agent/node/server, does not work for CA and user
      CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												   CertificateCacheService.class,
												   null);
      if(cacheservice==null) {
	log.warn(" Unable to get Certificate Cache service in findCert");
	return null;
      }

      if (param.isCertAuth) {
	List nameList = cacheservice.getX500NameFromNameMapping(commonName);
	if (nameList != null && nameList.size() > 0) {
	  X500Name dname = (X500Name)nameList.get(0);
	  return findCert(dname, lookupType, validOnly);
	}
	// else no cert has been created
	return null;
      }
      return findCert(CertificateUtility.getX500Name(getX500DN(commonName)), lookupType, validOnly);
    }

  public List findCert(X500Name dname) {
    return findCert(dname, KeyRingService.LOOKUP_KEYSTORE | KeyRingService.LOOKUP_LDAP, true);
  }

  public synchronized List findCert(X500Name dname,
				    int lookupType, boolean validOnly)
    {
      ArrayList certificateList = new ArrayList(0);
      CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												   CertificateCacheService.class,
												   null);
      if(cacheservice==null) {
	log.warn(" Unable to get Certificate cache service in findCert");
	return null;
      }
      String commonName = cacheservice.getCommonName(dname);

      List nameList = cacheservice.getX500NameFromNameMapping(commonName);
      boolean inNameMapping = cacheservice.presentInNameMapping(dname);
      if (!inNameMapping) {
	if (log.isDebugEnabled()) {
	  log.debug("DirectoryKeyStore.findCert(" + dname.toString()
		    + ") - x500 Name = not assigned yet" + lookupType);
	}
      }

      CertDirectoryServiceClient certFinder = certificateFinder;
      if ((lookupType & KeyRingService.LOOKUP_FORCE_LDAP_REFRESH) != 0
	  || (lookupType & KeyRingService.LOOKUP_LDAP) != 0) {
	if (log.isDebugEnabled()) {
	  log.debug("Retrieving LDAP client");
	}
	certFinder = getCertDirectoryServiceClient(dname);
      }

      // Refresh from LDAP service if requested
      if (((lookupType & KeyRingService.LOOKUP_FORCE_LDAP_REFRESH) != 0)
	  || !inNameMapping) {
	if (log.isDebugEnabled()) {
	  log.debug("Looking up certificate in LDAP");
	}
	// Update cache with certificates from LDAP.
	//String filter = "(cn=" + commonName + ")";
	String filter = parseDN(dname.getName());
	lookupCertInLDAP(filter, certFinder);

	// Looking up x500 name again
	inNameMapping =  cacheservice.presentInNameMapping(dname);
	if (!inNameMapping) {
	  if (log.isDebugEnabled()) {
	    log.debug("X500 name mapping not assigned yet." + dname.toString());
	  }
	}
      }

      if (!inNameMapping) {
	return certificateList;
      }

      List certList = internalFindCert(dname, lookupType, validOnly, certFinder);

      Iterator it = certList.iterator();
      CertificateStatus certstatus=null;
      while (it.hasNext()) {
	certstatus = (CertificateStatus) it.next();
	if((lookupType & KeyRingService.LOOKUP_LDAP) != 0 &&
	   (certstatus.getCertificateOrigin() == CertificateOrigin.CERT_ORI_LDAP
	    || certstatus.getCertificateOrigin() == CertificateOrigin.CERT_ORI_SSL)) {
	  // The caller accepts certificates from LDAP.
	  certificateList.add(certstatus);
	}
	else if ((lookupType & KeyRingService.LOOKUP_KEYSTORE) != 0 &&
		 certstatus.getCertificateOrigin() == CertificateOrigin.CERT_ORI_KEYSTORE) {
	  // The caller accepts certificates from the keystore.
	  certificateList.add(certstatus);
	}

	if (log.isDebugEnabled()) {
	  log.debug("DirectoryKeyStore.findCert: " + commonName
		    + " - Cert origin: " + certstatus.getCertificateOrigin());
	}
      }

      return certificateList;
    }

  private List internalFindCert(X500Name x500name,
				int lookupType,
				boolean validOnly,
				CertDirectoryServiceClient certFinder) {
    // Search in the local hash map.

    CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												 CertificateCacheService.class,
												 null);

    if(cacheservice==null) {
      log.error(" Unable to get Certificate cache service in internalFindCert");

    }
    List certList = null;
    if (validOnly){
      //if(cacheservice!=null){
      certList = getValidCertificates(x500name);
      //}
    }
    else{
      if(cacheservice!=null){
	certList = cacheservice.getCertificates(x500name);
      }
    }
    String commonName =null;
    if(cacheservice!=null){
      commonName= cacheservice.getCommonName(x500name);
    }

    if (log.isDebugEnabled()) {
      log.debug("Search key in local hash table:" + commonName
		+ " - found " +	(certList == null ? 0 : certList.size())
		+ " keys");
    }

    if (certList == null || certList.size() == 0) {
      if ((lookupType & KeyRingService.LOOKUP_FORCE_LDAP_REFRESH) != 0) {
	// We have just tried to lookup in LDAP so don't bother retrying again
      }
      else {
	// Look up in certificate directory service
	if ((lookupType & KeyRingService.LOOKUP_LDAP) != 0) {
	  //String filter = "(cn=" + commonName + ")";
	  String filter = parseDN(x500name.getName());
	  lookupCertInLDAP(filter, certFinder);
	  if (validOnly) {
	    //if(cacheservice!=null){
	    certList = getValidCertificates(x500name);
	    //}
	  }
	  else{
	    if(cacheservice!=null){
	      certList = cacheservice.getCertificates(x500name);
	    }
	  }

	  // Did we find certificates in LDAP?
	  if (certList == null || certList.size() == 0) {
	  }
	}
      }
    }
    
    return certList;
  }

  /** Lookup a certificate in the LDAP directory service.
   * A search filter is needed.
   * Examples of search filters:
   *     (cn=agent_name)
   *     (dn=distinguished_name)
   */
  private void lookupCertInLDAP(String filter, CertDirectoryServiceClient certFinder)
    {
      if (log.isDebugEnabled()) {
	log.debug(" lookupCertInLDAP of Directory keystore called :");
      }
      LdapEntry[] certs = null;
      CertificateStatus certstatus=null;
      String url = null;
      // Look in certificate directory service
      if (log.isDebugEnabled()) {
	log.debug("DirectoryKeyStore.findCert. Looking up ["
		  + filter + " ] in LDAP");
      }
      if (certFinder != null) {
	certs = certFinder.searchWithFilter(filter);
	url = certFinder.getDirectoryServiceURL();
      }
      else {
	if (log.isWarnEnabled()) {
	  log.warn("Certificate finder is null. Unable to perform the search: " + filter)    ;
	}
      }
      if(certs==null) {
	if (log.isErrorEnabled()) {
	  log.error("LDAP search failed for: " + filter + " (" + url + ")");
	}
	return;
      }
      else {
	if (certs.length == 0) {
	  if (log.isWarnEnabled()) {
	    log.warn("Failed to lookup certificate for " + filter + " in LDAP:"
		     + url);
	  }
	}
      }
      CertificateCacheService cacheservice=(CertificateCacheService)
	param.serviceBroker.getService(this,
				       CertificateCacheService.class,
				       null);
      CRLCacheService crlCacheservice=(CRLCacheService)
	param.serviceBroker.getService(this,
				       CRLCacheService.class,
				       null);
      if(cacheservice==null) {
	log.warn("Unable to get Certificate cache service  in lookupCertInLDAP ");
      }
      if(crlCacheservice==null) {
	log.warn("Unable to get CRL cache service  in lookupCertInLDAP ");
      }
     
      for (int i = 0 ; i < certs.length ; i++) {
	// Since the certificate comes from an LDAP server, it should be trusted
	// (because only a CA should publish certificates to the directory service,
	// but let's check just to make sure. There may be some cases where
	// a particular CA is not trusted locally.
	try {
	  // Richard: need to check whether the certificate already exist in
	  // cache. This happens with multiple CAs. When CRL is updated with
	  // status, next time findCert will lookup the revoked CA cert (cannot
	  // find any valid cert from cache) from LDAP and update it in the
	  // cache as trusted
	  X509Certificate certificate = certs[i].getCertificate();
	  boolean isRevoked = false;
	  //X500Name x500Name = nameMapping.getX500Name(certificate.getSubjectDN().getName());
	  X500Name x500Name = CertificateUtility.getX500Name(certificate.getSubjectDN().getName());

	  //if (x500Name != null) {
	
	  List certList =null;
	  if(cacheservice!=null) {
	    certList=cacheservice.getCertificates(x500Name);
	  }
	  if (certList != null) {
	    PublicKey publickey = certificate.getPublicKey();
	    for (int j = 0; j < certList.size(); j++) {
	      CertificateStatus cs = (CertificateStatus)certList.get(j);
	      if (cs.getCertificateTrust().equals(CertificateTrust.CERT_TRUST_REVOKED_CERT)) {
		if (log.isDebugEnabled()) {
		  log.debug("Revoked cert in cache found.");
		}
		if (cs.getCertificate().getPublicKey().equals(publickey)) {
		  if (log.isDebugEnabled()) {
		    log.debug("Cert from LDAP is already in cache, status REVOKED");
		  }
		  isRevoked = true;
		  break;
		}
	      }
	    }
	  }
	  if (isRevoked)
	    continue;

	  X509Certificate[] certChain = checkCertificateTrust(
	    certs[i].getCertificate(), certFinder);
	  if(certs[i].getStatus().equals(CertificateRevocationStatus.REVOKED)) {
	    certstatus = new CertificateStatus(certs[i].getCertificate(),false,
					       CertificateOrigin.CERT_ORI_LDAP,
					       certs[i].getCertificateType(),
					       CertificateTrust.CERT_TRUST_REVOKED_CERT,
					       null,
					       param.serviceBroker);
	    // certstatus.setValidity(false);
	  }
	  else {
	    certstatus = new CertificateStatus(certs[i].getCertificate(), true,
					       CertificateOrigin.CERT_ORI_LDAP,
					       certs[i].getCertificateType(),
					       CertificateTrust.CERT_TRUST_CA_SIGNED,
					       null,
					       param.serviceBroker);
	  }
	  if (log.isDebugEnabled()) {
	    log.debug("Updating cert cache with LDAP entry:" + filter);
	  }
	  if(cacheservice!=null) {
	    cacheservice.addCertificate(certstatus);
	    // Update Common Name to DN hashtable
	    cacheservice.addNameToNameMapping(certstatus);
	  }

	  if(certs[i].getCertificateType().equals(CertificateType.CERT_TYPE_CA)) {
	    if (log.isDebugEnabled()) {
	      log.debug("Certificate type is CA certificate");
	      log.debug("Updating CRLCache  with CA entry ");
	    }

	    certstatus.setCertFinder(certFinder);
	    if(crlCacheservice!=null) {
	      if(certFinder!=null) {
		crlCacheservice.addToCRLCache(certificate.getSubjectDN().getName(),
					      certFinder.getDirectoryServiceURL(),
					      certFinder.getDirectoryServiceType() );
	      }
	      else {
		log.warn(" Uable to add CA to CRL Cache as  there is no info about certfinder" +
			 certificate.getSubjectDN().getName());
	      }
	    }
	    else {
	      log.warn(" Uable to add CA to CRL Cache as CRL Cache service is null" +
		       certificate.getSubjectDN().getName());
	    }
	  }
	}
	catch (CertificateChainException e) {
	  if (log.isWarnEnabled()) {
	    log.warn("Found non trusted cert in LDAP directory! "
		     + filter + " - " + e);
	  }
	}
	catch (CertificateExpiredException e) {
	  // The certificate is trusted but it has expired.
	  if (log.isWarnEnabled()) {
	    log.warn("Certificate in chain has expired. "
		     + filter + " - " + e);
	  }
	}
	catch (CertificateNotYetValidException e) {
	  // The certificate is trusted but it is not yet valid. Add it to the cache
	  // because it may become valid when it is being used.
	  if (log.isWarnEnabled()) {
	    log.warn("Certificate in chain is not yet valid. "
		     + filter + " - " + e);
	  }
	  certstatus = new CertificateStatus(certs[i].getCertificate(), true,
					     CertificateOrigin.CERT_ORI_LDAP,
					     certs[i].getCertificateType(),
					     CertificateTrust.CERT_TRUST_CA_SIGNED,
					     null, param.serviceBroker);
	  if (log.isDebugEnabled()) {
	    log.debug("Updating cert cache with LDAP entry:" + filter);
	  }
	  if(cacheservice!=null) {
	    cacheservice.addCertificate(certstatus);
	    // Update Common Name to DN hashtable
	    cacheservice.addNameToNameMapping(certstatus);
	  }
	}
	catch (CertificateRevokedException certrevoked) {
	  if (log.isErrorEnabled()) {
	    log.error("Found cert in LDAP directory which has been revoked ! "
		      + filter + " - " + certrevoked);
	  }
	}
      }
    }

  /** Install a PKCS7 reply received from a certificate authority
   */
  public void installPkcs7Reply(String alias, InputStream inputstream)
    throws CertificateException, KeyStoreException, NoSuchAlgorithmException,
    UnrecoverableKeyException, IOException
    {

      SecurityManager security = System.getSecurityManager();
      if (security != null) {
	security.checkPermission(new KeyRingPermission("installPkcs7Reply"));
      }

      if (log.isDebugEnabled()) {
	log.debug("installPkcs7Reply for " + alias);
      }
      CertificateFactory cf = CertificateFactory.getInstance("X509");
      Collection collection = null;
      try {
	collection = cf.generateCertificates(inputstream);
      }
      catch (Exception e) {
	log.warn("Reply for " + alias + " is not a certificate");
	throw new CertificateException("Reply for " + alias + " is not a certificate");
      }

      if(collection.isEmpty()) {
	log.warn("Reply for " + alias + " has no certificate");
	throw new CertificateException("Reply has no certificate");
      }
      if (log.isDebugEnabled()) {
	Iterator it = collection.iterator();
	for (int i = 0 ; it.hasNext() ; i++) {
	  Object cert = it.next();
	  log.debug("Reply[" + i + "] - " + cert.getClass().getName());
	  log.debug( ((X509Certificate)cert).toString());
	}
      }
      X509Certificate certificateReply[] = new X509Certificate[0];
      certificateReply =
	(X509Certificate[])collection.toArray(certificateReply);

      installCertificate(alias, certificateReply);
    }

  

  public void installCertificate(String alias,
				 X509Certificate[] certificateChain)
    throws CertificateException, KeyStoreException,
    NoSuchAlgorithmException, UnrecoverableKeyException
    {
      X509Certificate certificateForImport[];

      CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												   CertificateCacheService.class,
												   null);
      if(cacheservice==null) {
	log.warn("Unable to get Certificate cache service in installCertificate:");
      }

      X509Certificate certificate =null;
      PrivateKey privatekey = null;
      if(cacheservice!=null) {
	certificate=cacheservice.getCertificate(alias);
	privatekey =cacheservice.getKey(alias);
      }

      if(certificate == null) {
	log.error(alias + " has no certificate. Cannot install certificate signed by CA.");
	throw new CertificateException(alias + " has no certificate");
      }
      if(privatekey==null) {
	log.error(alias + " has no Private key . Cannot install certificate signed by CA.");
	throw new CertificateException(alias + " has no Private Key ");
      }

      if(certificateChain.length == 1) {
	// There is no certificate chain.
	// We have to construct the chain first.
	if (log.isDebugEnabled()) {
	  log.debug("Certificate for alias :"+ alias
		    +"does not contain chain");
	}
	certificateForImport = establishCertChain(certificate,
						  certificateChain[0]);
	if (log.isDebugEnabled()) {
	  if(certificateForImport==null) {
	    log.debug("certificate for import is null:"); 
	  }
	  log.debug(" successfullly established chain");
	}
      }
      else {
	// The PKCS7 reply contains the certificate chain.
	// Validate the chain before proceeding.
	certificateForImport = validateReply(alias,
					     certificate, certificateChain);
      }
      if(certificateForImport != null) {
	if(cacheservice!=null){
	  cacheservice.setKeyEntry(alias, privatekey, certificateForImport);
	  log.debug(" adding certificate to certificate cache:"+ alias);
	  // The reply contains a certificate chain and it is valid
	  cacheservice.addCertificateToCache(alias, certificateForImport[0], privatekey);
	}
      }

    }

  /** @param certificate      Contains the self-signed certificate
   *  @param certificateReply Contains the certificate signed by the CA
   */
  private X509Certificate[] establishCertChain(X509Certificate certificate,
					       X509Certificate certificateReply)
    throws CertificateException, KeyStoreException
    {
      if (certificate == null) {
	log.error("establishCertChain: null certificate");
      }
      if (certificateReply == null) {
	log.error("establishCertChain: null certificate reply");
      }
      if(certificate != null) {
	java.security.PublicKey publickey = certificate.getPublicKey();
	java.security.PublicKey publickey1 = certificateReply.getPublicKey();
	if(!publickey.equals(publickey1)) {
	  String s = "Public keys in reply and keystore don't match";
	  log.warn(s);
	  throw new CertificateException(s);
	}
	if(certificateReply.equals(certificate)) {
	  String s1 = "Certificate reply and certificate in keystore are identical";
	  log.debug(s1);
	  throw new CertificateException(s1);
	}
      }
      return checkCertificateTrust(certificateReply);
    }

  public X509Certificate[] checkCertificateTrust(X509Certificate certificate)
    throws CertificateChainException, CertificateExpiredException,
    CertificateNotYetValidException, CertificateRevokedException
    {
      return checkCertificateTrust(certificate, null);
    }

  /** This method builds the certificate chain without verifying the certificate trust.
   */
  public X509Certificate[] buildCertificateChain(X509Certificate certificate) {
    Vector vector = new Vector(2);
    boolean ok = buildChain(certificate, vector, null, false);
    X509Certificate acertificate[] = new X509Certificate[vector.size()];
    int i = 0;
    for(int j = vector.size() - 1; j >= 0; j--) {
      acertificate[i] = (X509Certificate)vector.elementAt(j);
      i++;
    }
    return acertificate;
  }

  public X509Certificate[] checkCertificateTrust(
    X509Certificate certificate, CertDirectoryServiceClient certFinder)
    throws CertificateChainException, CertificateExpiredException,
    CertificateNotYetValidException, CertificateRevokedException
    {
      CertificateCacheService cacheservice=(CertificateCacheService)
	param.serviceBroker.getService(this,
				       CertificateCacheService.class,
				       null);
      
      if(cacheservice==null) {
	log.warn("Unable to get Certificate Cache service in checkCertificateTrust :");
      }
      boolean revoked = false;
      if(cacheservice!=null) {
	revoked=cacheservice.checkRevokedCache(certificate); 
      }
      if (revoked) {
	throw new CertificateRevokedException("Certificate revoked");
      }
      // Prepare a vector that will contain at least the entity certificate
      // and the signer.
      Vector vector = new Vector(2);
      boolean ok = buildChain(certificate, vector, certFinder, true);
      X509Certificate acertificate[] = new X509Certificate[vector.size()];
      if (ok) {
	int i = 0;
	for(int j = vector.size() - 1; j >= 0; j--) {
	  acertificate[i] = (X509Certificate)vector.elementAt(j);
	  // Check certificate validity
	  ((X509Certificate) acertificate[i]).checkValidity();
	  // Check key usage
	  if (i > 0) {
	    // does the cert has signing capability? otherwise should not be in
	    // the upper level of the chain
	    KeyUsageExtension keyusage = null;
	    try {
	      String s = OIDMap.getName(new ObjectIdentifier("2.5.29.15"));
	      if(s != null) {
		keyusage = (KeyUsageExtension)((X509CertImpl)acertificate[i]).get(s);
	      }
	    } catch (Exception ex) {
	      if (log.isErrorEnabled()) {
		log.error("Exception in getKeyUsage: " + ex.toString());
	      }
	    }
	    if (keyusage == null
		|| keyusage.getBits().length < KeyManagement.KEYUSAGE_CERT_SIGN_BIT
		|| !keyusage.getBits()[KeyManagement.KEYUSAGE_CERT_SIGN_BIT]) {
	      log.warn("Certificate does not have signing capability.");
	      throw new CertificateChainException("Certificate does not have signing capability.",
						  CertificateTrust.CERT_TRUST_NOT_TRUSTED);

	    }
	  }
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
	if (log.isInfoEnabled()) {
	  log.info("Certificate chain failed for: " + principal.getName() +
		   " Cause: " + cause.toString());
	}
	throw new CertificateChainException("Failed to establish chain from reply", cause);
      }
    }

  /*
    to be decided 
    private void initCRLCache()
    {
    try {
    if(caKeystore != null && caKeystore.size() > 0) {
    if (log.isDebugEnabled()) {
    log.debug("++++++ Initializing CRL Cache");
    }
    // Build a hash table that indexes keys in the CA keystore by DN
    initCRLCacheFromKeystore(caKeystore, param.caKeystorePassword);
    crlCache.startThread();
    }
    }
    catch (KeyStoreException e) {
    if (log.isWarnEnabled()) {
    log.warn("Unable to access CA keystore: " + e);
    }
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
  */

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
	String s = "Certificate reply does not contain public key for <" + alias + ">";
	log.warn(s);
	throw new CertificateException(s);
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

	if(l == certificateReply.length) {
	  log.warn("Incomplete certificate chain in reply for " + alias);
	  throw new CertificateException("Incomplete certificate chain in reply");
	}
      }

      for(int k = 0; k < certificateReply.length - 1; k++) {
	java.security.PublicKey publickey1 = certificateReply[k + 1].getPublicKey();
	try {
	  certificateReply[k].verify(publickey1);
	}
	catch(Exception exception) {
	  log.warn("Certificate chain in reply does not verify: "
		   + exception.getMessage());
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
  private boolean buildChain(X509Certificate x509certificate, Vector vector, boolean checkValidity)
    {
      return buildChain(x509certificate, vector, null, checkValidity);
    }

  private boolean buildChain(
    X509Certificate x509certificate, Vector vector, CertDirectoryServiceClient certFinder,
    boolean checkValidity)
    {
      boolean ret = internalBuildChain(x509certificate, vector, false, certFinder, checkValidity);
      if (log.isDebugEnabled()) {
	log.debug("Certificate trust=" + ret);
      }
      return ret;
    }

  /** Check whether at least one of the certificate in the certificate chain
   * is a trusted CA. The certificate chain must have previously been built with
   * checkCertificateTrust().
   * @param checkValidity - False if we don't care about the validity of the chain
   */
  private boolean internalBuildChain(X509Certificate x509certificate, 
				     Vector vector, 
				     boolean signedByAtLeastOneCA, 
				     CertDirectoryServiceClient certFinder,
				     boolean checkValidity)
    {
      Principal principal = x509certificate.getSubjectDN();
      Principal principalSigner = x509certificate.getIssuerDN();
      if (log.isDebugEnabled()) {
	log.debug("Build chain: " + principal.getName());
      }
      CertificateCacheService cacheservice=(CertificateCacheService)
	param.serviceBroker.getService(this,
				       CertificateCacheService.class,
				       null);
    
      if(cacheservice==null) {
	log.warn("Unable to get Certificate Cache service :");
      }
    
      X500Name x500NameSigner = CertificateUtility.getX500Name(principalSigner.getName());

      for (int i = 0; i < 2; i++) {
	List listSigner=null;
	if (i == 0) {
	  // get the signer from the cache if available
	  if(cacheservice!=null){
	    listSigner = cacheservice.getCertificates(x500NameSigner);
	  }

	  if(principal.equals(principalSigner)) {
	    if (log.isDebugEnabled()) {
	      log.debug("Certificate is self issued");
	    }

	    vector.addElement(x509certificate);

	    CertificateStatus cs = null;
	    if (listSigner != null && listSigner.size() > 0) {
	      cs = (CertificateStatus) listSigner.get(0);
	    }

	    if (cs != null && 
		cs.getCertificateType() == CertificateType.CERT_TYPE_CA) {
	      // This is a trusted certificate authority.
	      signedByAtLeastOneCA = true;
	    }

	    if (param.isCertAuth && cryptoClientPolicy.isRootCA()) {
	      // If DirectoryKeyStore is used in the context of a Certificate
	      // Authority, then a self-signed certificate is OK.
	      // Self-signed certificate should only be valid if it is type CA
	      String title = CertificateUtility.findAttribute(principalSigner.getName(), "t");
	      if (title != null && !title.equals(CertificateCache.CERT_TITLE_CA))
		return false;
          
	      return true;
	    }
	    else {
	      return signedByAtLeastOneCA;
	    }
	  }

	  if (listSigner == null) {
	    if (log.isDebugEnabled()) {
	      log.debug("Cache has not been filled for this certificate");
	    }
	    continue; // try again with refreshing the cache
	  } // end of if (listSigner == null)
	} else {
	  if (log.isDebugEnabled()) {
	    log.debug("Refreshing the cache for this certificate");
	  }

	  // One intermediate CA may not be in the local keystore.
	  // We need to go to the LDAP server to get the key if we haven't found
	  // a trusted CA yet.
	  if (!signedByAtLeastOneCA) {
	    if (log.isDebugEnabled()) {
	      log.debug("Looking up certificate in directory service");
	    }
	    String filter = parseDN(principalSigner.toString());

	    if (certFinder == null) {
	      String cname = principal.getName();
	      String ctype = CertificateUtility.findAttribute(cname, "t");
	      certFinder = certificateFinder;
	      X500Name dname = CertificateUtility.getX500Name(cname);
	      String commonname=null;
	      if(cacheservice!=null) {
		commonname=cacheservice.getCommonName(dname);
	      }
	      if (ctype != null && (ctype.equals(CertificateCache.CERT_TITLE_AGENT))) {
		// all other types should not have cross CA communication
		// for SSL the mechanism is different, the protocol handshake
		// requires the peer to supply the chain.
		certFinder = getCertDirectoryServiceClient(dname);
	      }
	      else if (ctype != null && ctype.equals(CertificateCache.CERT_TITLE_NODE)
		       && commonname.equals(NodeInfo.getNodeName())) {
		TrustedCaPolicy [] tc = cryptoClientPolicy.getIssuerPolicy();
		if (tc.length > 1) {
		  for (int j = 0; j < tc.length; j++) {
		    TrustedCaPolicy trustedCaPolicy = tc[j];
		    if (principalSigner.getName().equals(trustedCaPolicy.caDN)) {
		      if (log.isDebugEnabled()) {
			log.debug("Using signer: " + trustedCaPolicy.caDN + " ldap - "
				  + trustedCaPolicy.certDirectoryUrl);
		      }
		      certFinder = getCACertDirServiceClient(trustedCaPolicy.caDN);
		      break;
		    }
		  }
		}
	      }
	      if (certFinder == null) {
		if (log.isDebugEnabled()) {
		  log.debug("Failed to find cert finder for ldap, using default.");
		}
		certFinder = certificateFinder;
	      }
	    }

	    lookupCertInLDAP(filter, certFinder);

	    // Now, seach again.
	    if (checkValidity) {
	      //if(cacheservice!=null) {
	      listSigner = getValidCertificates(x500NameSigner);
	      //}
	    }
	    else {
	      if(cacheservice!=null) {
		listSigner = cacheservice.getCertificates(x500NameSigner);
	      }
	    }
	    if (listSigner == null) {
	      // It's OK not to have the full chain if at least one certificate in the
	      // chain is trusted.
	      return signedByAtLeastOneCA;
	    }
	  } else {
	    // It's OK not to have the full chain if at least one certificate in the
	    // chain is trusted.
	    return signedByAtLeastOneCA;
	  }
	} 
      
	Iterator it = listSigner.listIterator();
	// Loop through all the issuer keys and check to see if there is at least
	// one trusted key.
	while(it.hasNext()) {
	  CertificateStatus cs = (CertificateStatus) it.next();
	  // no need to check this if it is revoked
	  if (cs.getCertificateTrust().equals(CertificateTrust.CERT_TRUST_REVOKED_CERT)
	      && checkValidity) {
	    continue; // revoked, try the next one
	  }

	  X509Certificate x509certificate1 = (X509Certificate)cs.getCertificate();
	  java.security.PublicKey publickey = x509certificate1.getPublicKey();
	  try {
	    x509certificate.verify(publickey);
	  } catch(Exception exception) {
	    if (log.isInfoEnabled()) {
	      log.info("Unable to verify signature: "
		       + exception + " - "
		       + x509certificate1
		       + " - " + cs.getCertificateAlias());
	    }
	    continue;
	  }

	  if (cs.getCertificateType() == CertificateType.CERT_TYPE_CA) {
	    // The signing certificate is a CA. Therefore the certificate
	    // can be trusted.
	    signedByAtLeastOneCA = true;
	  }

	  if (log.isDebugEnabled()) {
	    log.debug("Found signing key: "
		      + x509certificate1.getSubjectDN().toString());
	  }

	  // Recursively build a certificate chain.
	  if(internalBuildChain(x509certificate1, vector, signedByAtLeastOneCA, certFinder, checkValidity)) {
	    vector.addElement(x509certificate);
	    return true;
	  }
	}
      } // end of for (int i = 0; i < 2; i++)
    
      if (log.isDebugEnabled()) {
	log.debug("No valid signer key");
      }
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
      PKCS10 request = generatePKCS10Request(certificate, signerAlias);
      String reply = CertificateUtility.base64encode(request.getEncoded(),
						     CertificateUtility.PKCS10HEADER,
						     CertificateUtility.PKCS10TRAILER);

      /*
	if (debug) {
	log.debug("GenerateSigningCertificateRequest:\n" + reply);
	}
      */
      return reply;
    }

  public PKCS10 generatePKCS10Request(X509Certificate certificate,
				      String signerAlias)
    throws IOException, SignatureException, NoSuchAlgorithmException, InvalidKeyException,
    KeyStoreException, UnrecoverableKeyException
    {
      PublicKey pk = certificate.getPublicKey();
      PKCS10 request = new PKCS10(pk);
      CertificateCacheService cacheservice=(CertificateCacheService)
	param.serviceBroker.getService(this,
				       CertificateCacheService.class,
				       null);

      if(cacheservice==null) {
	log.warn(" unabale to get Certificate Cache Service in generatePKCS10Reques");
      }

    
      // Get Signature object for certificate authority
      PrivateKey signerPrivateKey = null;
      X509Certificate cert =null;
      if(cacheservice!=null) {
	signerPrivateKey= cacheservice.getKey(signerAlias);
	cert = cacheservice.getCertificate(signerAlias);
      }

      //Signature signerSignature = Signature.getInstance(signerPrivateKey.getAlgorithm());
      // TODO: find signature algorithm that works with most crypto providers
      Signature signerSignature = Signature.getInstance("SHA1withRSA");
      signerSignature.initSign(signerPrivateKey);

      X500Name signerX500Name = new X500Name(cert.getSubjectDN().toString());
      X500Signer x500signer = new X500Signer(signerSignature, signerX500Name);

      try {
	if (log.isDebugEnabled()) {
	  log.debug("Signing certificate request with alias="
		    + signerAlias);
	}
	request.encodeAndSign(x500signer);
      }
      catch (CertificateException e) {
	if (log.isErrorEnabled()) {
	  log.error("Unable to sign certificate request." + e);
	}
      }
      return request;
    }


  protected synchronized PrivateKey addKeyPair(String commonName,
					       String keyAlias,
					       TrustedCaPolicy trustedCaPolicy)
    {
    
      CertificateAttributesPolicy certAttribPolicy =
	cryptoClientPolicy.getCertificateAttributesPolicy(trustedCaPolicy);
      X500Name dname = CertificateUtility.getX500Name(getX500DN(commonName, certAttribPolicy));
      return addKeyPair(dname, keyAlias, false, trustedCaPolicy);
    }

  private PrivateKey addCAKeyPair(X500Name dname, String keyAlias) {
    String alias = null;
    PrivateKey privatekey = null;
    CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												 CertificateCacheService.class,
												 null);

    if(cacheservice==null) {
      log.warn("Unable to get Certificate Cache service in addCAKeyPair");
    }


    
    if (!param.isCertAuth) {
      log.error("Cannot make CA cert, this node is not a CA");
      return null;
    }
    else {
      try {
	CertificateAttributesPolicy certAttribPolicy =
	  cryptoClientPolicy.getCertificateAttributesPolicy();
	// this must be a subordinate CA
	if (keyAlias != null) {
	  alias = keyAlias;
	  // lookup upper level CA's LDAP
	  if (log.isDebugEnabled()) {
	    log.debug("CA key already created, check upper level CA LDAP");
	  }

	  //String filter = "(cn=" + dname.getCommonName() + ")";
	  String filter = parseDN(dname.getName());
	  // there should be only one upper level CA, for now
	  CertDirectoryServiceClient certFinder =
	    getCACertDirServiceClient(cryptoClientPolicy.getIssuerPolicy()[0].caDN);
	  lookupCertInLDAP(filter, certFinder);

	  X509Certificate certificate =null;
	  if(cacheservice!=null) {
	    certificate=cacheservice.getCertificate(alias);
	  }
	  if (certificate != null) {
	    // look it up from keystore, if found in LDAP should have installed it
	    List keyList = null;
	    // if(cacheservice!=null) {
	    keyList=getValidPrivateKeys(dname);
	    //}
	    if (keyList != null && keyList.size() != 0)
	      privatekey = ((PrivateKeyCert)keyList.get(0)).getPrivateKey();
	    if (privatekey != null) {
	      CertificateStatus cs = ((PrivateKeyCert)keyList.get(0)).getCertificateStatus();
	      X509Certificate [] certForImport = establishCertChain(certificate,
								    cs.getCertificate());
	      if(cacheservice!=null) {
		cacheservice.setKeyEntry(alias, privatekey, certForImport);
		cacheservice.saveCertificateInTrustedKeyStore((X509Certificate)cacheservice.getCertificate(alias),
							      alias);
	      }
	      return privatekey;
	    }
	  }
	  // else send the request again
	}
	else {
	  alias = makeKeyPair(dname, true, certAttribPolicy);
	}

	// does it need to be submitted to somewhere else to handle?
	if (cryptoClientPolicy.isRootCA()) {
	  if (log.isDebugEnabled()) {
	    log.debug("creating root CA.");
	  }
	  
	  if(cacheservice!=null){
	    // Save the certificate in the trusted CA keystore
	    cacheservice.saveCertificateInTrustedKeyStore((X509Certificate)
							  cacheservice.getCertificate(alias),
							  alias);
	    privatekey = cacheservice.getKey(alias);
	  }
	}
	// else submit to upper level CA
	else {
	  String request =
	    generateSigningCertificateRequest((X509Certificate)
					      cacheservice.getCertificate(alias),
					      alias);
	  if (log.isDebugEnabled()) {
	    log.debug("Sending PKCS10 request to root CA to sign this CA.");
	  }
	  TrustedCaPolicy [] tc = cryptoClientPolicy.getIssuerPolicy();
	  String reply = sendPKCS(request, "PKCS10", tc[0]);
	  privatekey = processPkcs7Reply(alias, reply);
	  if (privatekey != null){
	    if(cacheservice!=null){
	      cacheservice.saveCertificateInTrustedKeyStore((X509Certificate)
							    cacheservice.getCertificate(alias),
							    alias);
	    }
	  }
	}
      } catch (Exception e) {
	e.printStackTrace();
	if (log.isDebugEnabled()) {
	  log.warn("Unable to create key: " + dname + " - Reason:" + e, new Throwable());
	}
      }

      return privatekey;
    }
  }

  private PrivateKey addKeyPairOnCA(X500Name dname, String keyAlias) {
    String alias = null;
    PrivateKey privatekey = null;
    if (log.isDebugEnabled()) {
      log.debug("Creating cert on CA: " + dname.toString() + " : " + keyAlias);
    }
    CertificateCacheService cacheservice=(CertificateCacheService)
      param.serviceBroker.getService(this,
				     CertificateCacheService.class,
				     null);

    if(cacheservice==null) {
      log.warn("Unable to get Certificate Cache service in addKeyPairOn"); 
    }
    try {
      X500Name [] caDNs = configParser.getCaDNs();
      CertificateAttributesPolicy certAttribPolicy =
	cryptoClientPolicy.getCertificateAttributesPolicy();
      if (caDNs.length == 0) {
	if (log.isDebugEnabled()) {
	  log.debug("No CA key created yet, the certificate can not be created.");
	}
	/*
        if (cacheservice.getCommonName(dname).equals(NodeInfo.getHostName())) {
          if (log.isDebugEnabled())
            log.debug("Creating self signed host key");
          makeKeyPair(dname, false, certAttribPolicy);
        }
	*/
        return null;
      }
      String caDN = configParser.getCaDNs()[0].getName();
      // is the CA key valid
      if (!cryptoClientPolicy.isRootCA()) {
	List certList = null;
	//if(cacheservice!=null) {
	certList=getValidCertificates(configParser.getCaDNs()[0]);
	//}
	if (certList == null || certList.size() == 0) {
	  if (log.isDebugEnabled()) {
	    log.debug("CA key created but is not approved by upper level CA yet.");
	  }
	  String caCommonName=null;
	  if(cacheservice!=null) {
	    caCommonName=cacheservice.getCommonName(configParser.getCaDNs()[0]);
	  }
	  String caAlias = findAlias(caCommonName);
	  if (log.isDebugEnabled()) {
	    log.debug("CA alias: " + caAlias);
	  }
	  addCAKeyPair(configParser.getCaDNs()[0], caAlias);
	  return null;
	}
      }

      if (keyAlias != null)
	alias = keyAlias;
      else
	alias = makeKeyPair(dname, false, certAttribPolicy);

      // sign it locally

      CertificateManagementService km = (CertificateManagementService)
	param.serviceBroker.getService(
	  new CertificateManagementServiceClientImpl(caDN),
	  CertificateManagementService.class,
	  null);
      if (log.isDebugEnabled()) {
	log.debug("Signing certificate locally with " + caDN);
      }
      X509Certificate cert=null;
      if(cacheservice!=null) {
	cert=cacheservice.getCertificate(alias);
      }
      X509CertImpl certImpl = km.signX509Certificate(
	generatePKCS10Request(cert,
			      alias));

      // publish CA certificate to LDAP
      km.publishCertificate(certImpl);

      // install
      installCertificate(alias, new X509Certificate[] {certImpl});
      if(cacheservice!=null){
	privatekey = cacheservice.getKey(alias);
      }
    } catch (Exception e) {
      if (log.isDebugEnabled()) {
	log.warn("Unable to create key: " + dname + " - Reason:" + e,new Throwable());
      }
    }
    return privatekey;
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
					       String keyAlias,
					       boolean isCACert,
					       TrustedCaPolicy trustedCaPolicy)
    {
    
      String request = "";
      String reply = "";
      CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												   CertificateCacheService.class,
												   null);

      if(cacheservice==null) {
	log.warn("Unable to get Certificate Cache in  addKeyPair");
      }
    
      //is node?
      String nodeName = NodeInfo.getNodeName();
      String commonName = null;
      if(cacheservice!=null){
	commonName = cacheservice.getCommonName(dname);
      }

      if (log.isDebugEnabled()) {
	log.debug("Creating key pair for "
		  + dname + " - Node name:" + nodeName
		  + " - Common Name=" + commonName);
      }

      if (nodeName == null) {
	if (log.isErrorEnabled()) {
	  log.error("Cannot get node name");
	}
	return null;
      }
      String alias = null;
      PrivateKey privatekey = null;

    /**
     * Handle CA cert
     */
    if (isCACert) {
      return addCAKeyPair(dname, keyAlias);
    }
    else if (param.isCertAuth) {
      return addKeyPairOnCA(dname, keyAlias);
    }

      try {
	/* If the requested key is for the node, the key is self signed.
	 * If the requested key is for an agent, and the node is a signer,
	 *  then the agent key is signed by the node.
	 * If the node is not a signer, the requested key is self-signed.
	 */
	String title = CertificateUtility.findAttribute(dname.getName(), "t");
	CertificateAttributesPolicy certAttribPolicy =
	  cryptoClientPolicy.getCertificateAttributesPolicy(trustedCaPolicy);
	X500Name nodex500name = CertificateUtility.getX500Name(getX500DN(nodeName, certAttribPolicy));
	if(commonName.equals(nodeName)/* || commonName.equals(NodeInfo.getHostName())*/
	   || (title != null && title.equals(CertificateCache.CERT_TITLE_USER))
	   || !certAttribPolicy.nodeIsSigner) {
	  // Create a self-signed key and send it to the CA.
	  if (keyAlias != null) {
	    // Do not create key. There is already one in the keystore.
	    alias = keyAlias;
	    if (log.isDebugEnabled()) {
	      log.debug("Using existing key: " + keyAlias);
	    }
	    // First, go to the CA to see if the CA has already signed the key.
	    // In that case, there is no need to send a PKCS10 request.
	    return getNodeCert(nodex500name, trustedCaPolicy);
	  }
	  else {
	    if (log.isDebugEnabled()) {
	      log.debug("Creating key pair for node: " + nodeName);
	    }
	    alias = makeKeyPair(dname, false, certAttribPolicy);
	  }
	  // At this point, the key pair has been added to the keystore,
	  // but we don't have the reply from the certificate authority yet.
	  // Send the public key to the Certificate Authority (PKCS10)
	  if (!param.isCertAuth) {
	    X509Certificate cert=null;
	    if(cacheservice!=null) {
	      cert= cacheservice.getCertificate(alias);
	    }
	    request =
	      generateSigningCertificateRequest(cert,
						alias);
	    if (log.isDebugEnabled()) {
	      log.debug("Sending PKCS10 request to CA");
	    }
	    reply = sendPKCS(request, "PKCS10", trustedCaPolicy);
	  }
	}
	else {
	  PrivateKey nodeprivatekey = null;
	  try {
	    nodeprivatekey = getNodeCert(nodex500name, trustedCaPolicy);
	  } catch (Exception nex) {
	    if (log.isWarnEnabled())
	      log.warn("Failed to get node cert. Reason: " + nex);
	  }
	  if (nodeprivatekey == null) {
	    if (commonName.equals(NodeInfo.getHostName())) {
	      if (log.isDebugEnabled())
		log.debug("Creating self signed host key");
	      makeKeyPair(dname, false, certAttribPolicy);
	    }
	    return null;
	  }

	  // The Node key should exist now
	  if (log.isDebugEnabled()) {
	    log.debug("Searching node key again: " + nodeName);
	  }
	  List nodex509List = findCert(nodex500name,
				       KeyRingService.LOOKUP_KEYSTORE,
				       true);
	  X509Certificate nodex509 = null;
	  if (nodex509List.size() > 0) {
	    nodex509 =
	      ((CertificateStatus) nodex509List.get(0)).getCertificate();
	  }
	  if (log.isDebugEnabled()) {
	    log.debug("Node key is: " + nodex509);
	  }
	  if (nodex509 == null) {
	    // There was a problem during the generation of the node's key.
	    // Stop the procedure.
	    if (log.isErrorEnabled()) {
	      log.error("Unable to get node's key");
	    }
	    return null;
	  }
	  if (keyAlias != null) {
	    // Do not create key. There is already one in the keystore.
	    alias = keyAlias;
	    if (log.isDebugEnabled()) {
	      log.debug("Using existing key: " + keyAlias);
	    }
	  }
	  else {
	    if (log.isDebugEnabled()) {
	      log.debug("Creating key pair for agent: " + dname);
	    }
	    alias = makeKeyPair(dname, false, certAttribPolicy);
	  }
	  // Generate a pkcs10 request, then sign it with node's key
	  //String nodeAlias = findAlias(nodeName);
	  X509Certificate cert=null;
	  if(cacheservice!=null) {
	    cert= cacheservice.getCertificate(alias);
	  }
	
	  request =
	    generateSigningCertificateRequest(cert,
					      alias);
	  // Sign PKCS10 request with node key and send agent cert to CA
	  reply = signPKCS(request, nodex509.getSubjectDN().getName(), trustedCaPolicy);
	}
      } catch (Exception e) {
	if (log.isErrorEnabled()) {
	  log.error("Unable to create key in addKeyPair: " + dname + " - Reason:", e);
	}
      }

      if (alias != null) {
	privatekey = processPkcs7Reply(alias, reply);
      }
      return privatekey;
    }

  private PrivateKey getNodeCert(X500Name nodex500name, TrustedCaPolicy trustedCaPolicy)
    throws Exception {
    PrivateKey nodeprivatekey = null;
    X509Certificate nodex509 = null;
    String request = "";
    String reply = "";
    CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												 CertificateCacheService.class,
												 null);

    if(cacheservice==null) {
      log.warn(" Unable to get Certificate Cache Service in getNodeCert");
    }
    
    // check if node cert exist
    if (log.isDebugEnabled()) {
      log.debug("Searching node key: " + nodex500name.toString());
    }

    String nodeAlias = null;
    if(cacheservice!=null) {
      nodeAlias=cacheservice.findAlias(nodex500name);
    }
    if (nodeAlias != null) {
      List nodex509List = findCert(nodex500name,
				   KeyRingService.LOOKUP_KEYSTORE,
				   true);
      if (nodex509List.size() > 0) {
	nodex509 = ((CertificateStatus)nodex509List.get(0)).getCertificate();
      }
      if(nodex509 == null) {
	// maybe approved and in LDAP?
	nodex509List = findCert(nodex500name, KeyRingService.LOOKUP_LDAP, true);
	if (nodex509List.size() > 0) {
	  nodex509 = ((CertificateStatus)nodex509List.get(0)).getCertificate();
	}
	if (nodex509 != null) {
	  // install the certificate into keystore

	  X509Certificate certificate = null;
	  if(cacheservice!=null) {
	    certificate=cacheservice.getCertificate(nodeAlias);
	  }
	    
	  if (certificate == null) {
	    throw new CertificateException(nodeAlias + "has no certificate.");
	  }
	  X509Certificate [] certForImport = establishCertChain(certificate, nodex509);
	  if (nodeprivatekey != null){
	    if(cacheservice!=null) {
	      cacheservice.setKeyEntry(nodeAlias, nodeprivatekey, certForImport);
	    }
	  }
	}
      }

      if(nodex509 == null) {
	// Richard -- not in LDAP or local keystore
	// might be still pending or denied
	// check with CA, if nothing found then create new key pair
	// if still pending or denied, return null
	if (log.isDebugEnabled()) {
	  log.debug("Node certificate not found, checking pending status.");
	}
	
	X509Certificate cert=null;
	if(cacheservice!=null) {
	  cert=cacheservice.getCertificate(nodeAlias);
	}
	request =
	  generateSigningCertificateRequest(cert,
					    nodeAlias);
	if (log.isDebugEnabled()) {
	  log.debug("Sending PKCS10 request to CA");
	}
	reply = sendPKCS(request, "PKCS10", trustedCaPolicy);
	// check status
	String strStat = "status=";
	int statindex = reply.indexOf(strStat);
	if (statindex >= 0) {
	  // in the pending mode
	  statindex += strStat.length();
	  int status = Integer.parseInt(reply.substring(statindex,
							statindex + 1));
	  if (log.isDebugEnabled()) {
	    switch (status) {
	    case KeyManagement.PENDING_STATUS_PENDING:
	      log.debug("Certificate is pending for approval.");
	      break;
	    case KeyManagement.PENDING_STATUS_DENIED:
	      log.debug("Certificate is denied by CA.");
	      break;
	    case KeyManagement.PENDING_STATUS_APPROVED:
	      log.debug("Certificate is approved by CA.");
	      break;
	    default:
	      log.debug("Unknown certificate status:" + status);
	    }
	  }
	  // else approved, why not certificate in the LDAP?

	  return null;
	}
	else {
	  // get back the reply right away
	  return processPkcs7Reply(nodeAlias, reply);
	}
      }
      if(cacheservice!=null){
	nodeprivatekey = cacheservice.getKey(nodeAlias);
      }
    }
    else {

      //we don't have a node key pair, so make it
      if (log.isDebugEnabled()) {
	log.debug("Recursively creating key pair for node: "
		  + nodex500name);
      }
      nodeprivatekey = addKeyPair(nodex500name, null, false, trustedCaPolicy);
      if (log.isDebugEnabled()) {
	log.debug("Node key created: " + nodex500name);
      }
    }
    return nodeprivatekey;
  }

  private PrivateKey processPkcs7Reply(String alias, String reply) {
    
    PrivateKey privatekey = null;
    CertificateCacheService cacheservice=(CertificateCacheService)
      param.serviceBroker.getService(this,
				     CertificateCacheService.class,
				     null);
    
    if(cacheservice==null) {
      log.warn("Unable to get Certificate cache Service in processPkcs7Reply");
    }
    // Richard -- check whether pending
    String strStat = "status=";
    int statindex = reply.indexOf(strStat);
    if (statindex >= 0) {
      if (log.isDebugEnabled()) {
	log.debug("processPkcs7Reply: certificate in pending mode. ");
      }
      return null;
    }
    if (reply.length() == 0)
      return null;

    try{
      installPkcs7Reply(alias, new ByteArrayInputStream(reply.getBytes()));
      log.debug(" Install Pkcs & reply done ");
      if(cacheservice!=null){
	privatekey = cacheservice.getKey(alias);
      }
    } catch (java.security.cert.CertificateNotYetValidException e) {
      if (log.isWarnEnabled()) {
	Date d = new Date();
	log.warn("Error: Certificate not yet valid for:"
		 + alias
		 + " (" + e + ")"
		 + " Current date is " + d.toString());
      }
    } catch(Exception e) {
      if (log.isWarnEnabled()) {
	log.warn("Can't get certificate for " + alias + " Reason: " + e
		 + ". Reply from CA is:" + reply ,new Throwable());
	  
      }
    }
    return privatekey;
  }

  public String getAlias(X509Certificate clientX509)
    {
    
      String alias = null;
      CertificateCacheService cacheservice=(CertificateCacheService)
	param.serviceBroker.getService(this,
				       CertificateCacheService.class,
				       null);
     
      if(cacheservice==null) {
	log.warn("Unable to get Certificate cache Service in getAlias");
      }
      try {
	String alg = "MD5"; // TODO: make this dynamic
	MessageDigest md = createDigest(alg, clientX509.getTBSCertificate());
	byte[] digest = md.digest();

	String prefix =null;
	if(cacheservice!=null){
	  prefix=cacheservice.getCommonName(clientX509);
	}
	alias = prefix + "-" + toHex(digest);
      }
      catch (Exception e) {
	log.error("Unable to get alias: " + e);
      }
      return alias;
    }

  public List findCert(Principal p) {
    try {
      return findCert(CertificateUtility.getX500Name(p.getName()),
		      KeyRingService.LOOKUP_KEYSTORE | KeyRingService.LOOKUP_LDAP,
		      true);
    }
    catch (Exception e) {
      log.warn("Unable to find certificate for " + p.toString() + ". Reason:" + e);
    }
    return null;
  }

  public List findCert(String name) {
    List certificateList = null;
    try {
      certificateList =
	findCert(name, KeyRingService.LOOKUP_KEYSTORE | KeyRingService.LOOKUP_LDAP);
    }
    catch (Exception e) {
      log.warn("Unable to find certificate for " + name + ". Reason:" + e);
    }
    return certificateList;
  }

  /*
  // filter out the certs that is not issued by the trusted CA
  public List findCert(List certificateList, TrustedCaPolicy trustedCaPolicy) {
  if (certificateList == null || certificateList.size() == 0 || trustedCaPolicy == null)
  return certificateList;

  List filteredList = new ArrayList();
  String trustedSigner = trustedCaPolicy.caDN;

  // do not use checkCertificateTrust, it is too much for
  // this purpose and the certs are already found trusted
  for (int i = 0; i < certificateList.size(); i++) {
  CertificateStatus cs = (CertificateStatus)certificateList.get(i);
  X509Certificate x509certificate = cs.getCertificate();
  if (cs.getCertificateTrust() != CertificateTrust.CERT_TRUST_CA_SIGNED
  && cs.getCertificateTrust() != CertificateTrust.CERT_TRUST_CA_CERT)
  continue;

  if (x509certificate.getSubjectDN().getName().equals(trustedSigner)) {
  filteredList.add(cs);
  continue;
  }
  Principal principalSigner = x509certificate.getIssuerDN();
  // if self signed return
  if (principalSigner.equals(x509certificate.getSubjectDN()))
  continue;

  X500Name x500NameSigner = getX500Name(principalSigner.getName());
  List signerList = certCache.getCertificates(x500NameSigner);
  signerList = findCert(signerList, trustedCaPolicy);

  // is it a signer in the chain?
  if (signerList != null && signerList.size() != 0) {
  filteredList.add(cs);
  }
  }
  return filteredList;
  }
  */

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
  private String getNextAlias(String name)
    {

    
      String alias = name.toLowerCase() + "-";
      int nextIndex = 1;
      int ind;
      CertificateCacheService cacheservice=(CertificateCacheService)
	param.serviceBroker.getService(this,
				       CertificateCacheService.class,
				       null);
    
      if(cacheservice==null) {
	log.warn("Unable to get Certificate cache Service in getNextAlias");
      }
    
      try {
	Enumeration list = null;
	if(cacheservice!=null){
	  list=cacheservice. getAliasList();
	}

	while (list.hasMoreElements()) {
	  //build up the hashMap
	  String a = (String)list.nextElement();
	  if (a.startsWith(alias)) {
	    //Extract index
	    try {
	      ind = Integer.valueOf(a.substring(alias.length())).intValue();
	    }
	    catch (NumberFormatException e) {
	      continue;
	    }
	    if (log.isDebugEnabled()) {
	      log.debug("Alias: " + alias + " - val: " + ind);
	    }
	    if (ind >= nextIndex) {
	      nextIndex = ind + 1;
	    }
	  }
	}
      } catch(Exception e) {
	log.error("Unable to get next alias:" + e.toString());
      }
      alias = alias + nextIndex;
      if (log.isDebugEnabled()) {
	log.debug("Next alias for " + name  + " is " + alias);
      }
      return alias;
    }

  public String makeKeyPair(X500Name dname,
			    boolean isCACert,
			    CertificateAttributesPolicy certAttribPolicy)
    throws Exception
    {

      CertificateCacheService cacheservice=(CertificateCacheService)
	param.serviceBroker.getService(this,
				       CertificateCacheService.class,
				       null);
    
      if(cacheservice==null) {
	log.warn("Unable to get Certificate cache Service in makeKeyPair");
      }
    
      //generate key pair.
      if (log.isDebugEnabled()) {
	log.debug("makeKeyPair: " + dname);
      }
      String commonName = null;
      if(cacheservice!=null) {
	commonName=cacheservice.getCommonName(dname);
      }

      // check whether there is self-signed certificate
      // reuse it
      // if a cert is deny, expired, revoke, etc, status should not be unknown
      if (!isCACert) {
	List certList =null;
	if(cacheservice!=null) {
	  certList=cacheservice.getCertificates(dname);
	}
	for (int i = 0; certList != null && i < certList.size(); i++) {
	  CertificateStatus cs = (CertificateStatus)certList.get(i);
	  if (cs.getCertificateTrust() == CertificateTrust.CERT_TRUST_SELF_SIGNED
	      && cs.getCertificateType() == CertificateType.CERT_TYPE_END_ENTITY) {
	    String alias = cs.getCertificateAlias();
	    log.debug("Reusing alias: " + alias);
	    return alias;
	  }

	}
      }

      String alias = getNextAlias(commonName);

      if (log.isDebugEnabled()) {
	log.debug("Make key pair:" + alias + ":" + dname.toString());
      }
      doGenKeyPair(alias, dname, isCACert, certAttribPolicy);
      return alias;
    }

  /** Generate a key pair and a self-signed certificate */
  public void doGenKeyPair(String alias,
			   X500Name dname,
			   boolean isCACert,
			   CertificateAttributesPolicy certAttribPolicy)
    throws Exception
    {
      String keyAlgName = certAttribPolicy.keyAlgName;
      int keysize = certAttribPolicy.keysize;
      String sigAlgName = certAttribPolicy.sigAlgName;
      long howLong = certAttribPolicy.howLong;
      CertificateCacheService cacheservice=(CertificateCacheService)
	param.serviceBroker.getService(this,
				       CertificateCacheService.class,
				       null);
     
      if(cacheservice==null) {
	log.warn("Unable to get Certificate cache Service in doGenKeyPair");
      }
    
      if(sigAlgName == null)
	if(keyAlgName.equalsIgnoreCase("DSA"))
	  sigAlgName = "SHA1WithDSA";
	else
	  if(keyAlgName.equalsIgnoreCase("RSA"))
	    sigAlgName = "MD5WithRSA";
	  else
	    throw new Exception("Cannot derive signature algorithm");
      KeyCertGenerator certandkeygen = new KeyCertGenerator(keyAlgName,
							    sigAlgName, null,
							    param.serviceBroker);
      if (log.isDebugEnabled()) {
	log.debug("Generating " + keysize + " bit " + keyAlgName
		  + " key pair and " + "self-signed certificate ("
		  + sigAlgName + ")");
	log.debug("\tfor: " + dname + " - alias:" + alias);
      }
      certandkeygen.generate(keysize);
      PrivateKey privatekey = certandkeygen.getPrivateKey();
      X509Certificate ax509certificate[] = new X509Certificate[1];

      long envelope = certAttribPolicy.regenEnvelope;
      boolean isSigner = false;
      // isCA and is CA DN
      if (isCACert)
	isSigner = true;
      // is not CA but is node and nodeIsSigner
      else {
	String commonname=null;
	if(cacheservice!=null) {
	  commonname=cacheservice.getCommonName(dname);
	}
	if(commonname!=null){
	  isSigner = commonname.equals(NodeInfo.getNodeName())
	    && certAttribPolicy.nodeIsSigner;
	}
      }

      ax509certificate[0] = certandkeygen.getSelfCertificate(dname, envelope, howLong, isSigner);
      if(cacheservice!=null) {
	cacheservice.setKeyEntry(alias, privatekey, ax509certificate);
      }

      CertificateType certificateType = null;
      CertificateTrust certificateTrust = null;
      if (!isCACert) {
	// Add the certificate to the certificate cache. The key cannot be used
	// yet because it has not been signed by the Certificate Authority.
	certificateType = CertificateType.CERT_TYPE_END_ENTITY;
	certificateTrust = CertificateTrust.CERT_TRUST_SELF_SIGNED;
      }
      else {
	// This is a certificate authority, so the CA is trusting itself.
	certificateType= CertificateType.CERT_TYPE_CA;
	if (cryptoClientPolicy.isRootCA())
	  certificateTrust= CertificateTrust.CERT_TRUST_CA_CERT;
	else
	  certificateTrust= CertificateTrust.CERT_TRUST_SELF_SIGNED;
      }
      CertificateStatus certstatus =
	new CertificateStatus(ax509certificate[0], true,
			      CertificateOrigin.CERT_ORI_KEYSTORE,
			      certificateType,
			      certificateTrust, alias,
			      param.serviceBroker);
      certstatus.setPKCS10Date(new Date());
      if (log.isDebugEnabled()) {
	log.debug("doGenKeyPair: add Private Key");
      }
      
      if(cacheservice!=null) {
	cacheservice.addCertificate(certstatus);
	cacheservice.addPrivateKey(privatekey, certstatus);
	// Update Common Name to DN hashtable
	cacheservice.addNameToNameMapping(certstatus);
      }
      else {
	log.warn("Unable to get Certificate cache service in doGenKeyPair..Cannot add certificate to certificate cache");
      }
    }

  /**
   * This function should only be used by non user or non CA
   */
  public void checkOrMakeCert(String commonName) {
    
    if (param.isCertAuth) {
      X500Name dname = CertificateUtility.getX500Name(getX500DN(commonName));
      checkOrMakeCert(dname, false, null);
      return;
    }

    // go through all the trusted policies
    // more than one certificate may be acquired
    TrustedCaPolicy[] trustedCaPolicy = cryptoClientPolicy.getIssuerPolicy();

    // this only happens in unzip & run, originally there is no trusted CA policy
    if (System.getProperty("org.cougaar.core.autoconfig", "false").equals("true")) {
      requestedIdentities.put(commonName, commonName);
      if (log.isDebugEnabled()) {
        log.debug("saving " + commonName + " to requested identity cache.");
      }
    }

    // create a dummy host key so that https server can be started
    if (commonName.equals(NodeInfo.getHostName())) {
      try {
        CertificateCacheService cacheservice=(CertificateCacheService)
          param.serviceBroker.getService(this,
                                         CertificateCacheService.class,
                                         null);

        if(cacheservice==null) {
          log.warn("Unable to get Certificate cache Service in checkOrMakeCert");
        }
        CertificateAttributesPolicy cap = cryptoClientPolicy.getCertificateAttributesPolicy();
        X500Name dname = null;
        dname = new X500Name(getX500DN(commonName, cap));

        // only do this if there is no host key present
        if (cacheservice.findAlias(dname) == null) {
          if (log.isDebugEnabled()) {
            log.debug("Creating self signed host key");
          }
          makeKeyPair(dname, false, cap);
        }
      } catch (Exception ex) {
        if (log.isWarnEnabled()) {
          log.warn("Failed to create host key. " + ex);
        }
      }
    }

    for (int i = 0; i < trustedCaPolicy.length; i++) {
      X500Name dname = CertificateUtility.getX500Name(getX500DN
						      (commonName,
						       cryptoClientPolicy.getCertificateAttributesPolicy(trustedCaPolicy[i])));
      checkOrMakeCert(dname, false, trustedCaPolicy[i]);
    }
  }

  /**
   * This function should only be used by user or CA identity request
   */
  public void checkOrMakeCert(X500Name dname, boolean isCACert) {
    checkOrMakeCert(dname, isCACert, null);
  }

  public synchronized void checkOrMakeCert(X500Name dname, boolean isCACert, TrustedCaPolicy trustedCaPolicy) {
    if (log.isDebugEnabled()) {
      log.debug("CheckOrMakeCert: " + dname.toString() );
	
    }
    
    /*
      if (!param.isCertAuth) {
      if (CertificateUtility.findAttribute(dname.getName(), "t").equals(CERT_TITLE_AGENT)) {
      try {
      testDataProtection(dname.getCommonName(), true);
      testDataProtection(dname.getCommonName(), false);
      done = true;
      } catch (Exception ex) {
      }
      }
      }
    */

    CertificateCacheService cacheservice=(CertificateCacheService)
      param.serviceBroker.getService(this,
				     CertificateCacheService.class,
				     null);
    
    if(cacheservice==null) {
      log.warn("Unable to get Certificate cache Service in checkOrMakeCert");
    }

    //check first
    List certificateList = null;
    try{
      certificateList = findCert(dname,
				 KeyRingService.LOOKUP_KEYSTORE,
				 true);
      if(certificateList != null && certificateList.size() != 0) {
	//checkOrMakeHostKey();
	String commonname=null;
	if(cacheservice!=null) {
	  commonname=cacheservice.getCommonName(dname);
	}
	else {
	  log.debug("cacheservice is null in checkOrMakeCert");

	}
	if(commonname!=null){
	  log.debug("common name in checkOrMakeCert is :"+commonname);
	}
	else {
	  log.debug("common name in checkOrMakeCert is :NULL");
	}
	  
        if (commonname!=null && commonname.equals(NodeInfo.getNodeName())) {
          if (param.isCertAuth) {
            X500Name [] caDNs = configParser.getCaDNs();
            if (caDNs.length != 0) {
              publishCAToLdap(caDNs[0].getName());
            }
          }
          handleRequestedIdentities(trustedCaPolicy);
        }
	return;
      }
      else {
	log.debug("Find cert returned no certificate "
		  + dname.toString());
      }
    }
    catch(Exception e){
      log.warn("Can't locate the certificate for:"
	       + dname.toString()
	       +". Reason:"+e+". Generating new one...", e);
    }
    if (log.isDebugEnabled()) {
      log.debug("checkOrMakeCert: creating key for "
		+ dname.toString());
    }
    //we'll have to make one
    PrivateKey privatekey = addKeyPair(dname, null, isCACert, trustedCaPolicy);
    if (privatekey != null) {
      String commonname=cacheservice.getCommonName(dname);
      // only do it for node cert, otherwise will have infinite loop here
      if (commonname.equals(NodeInfo.getNodeName())) {
        handleRequestedIdentities(trustedCaPolicy);
      }
    }
  }

  private void handleRequestedIdentities(TrustedCaPolicy trustedCaPolicy) {
    // for unzip & run
    // after grabbing CA info from CA, plugin will request node
    // certificate
      // flag for unzip & run
    if (System.getProperty("org.cougaar.core.autoconfig", "false").equals("true")) {
      for (Enumeration en = requestedIdentities.keys(); en.hasMoreElements(); ) {
        String cname = (String)en.nextElement();
        // no need to do dname again
        if (cname.equals(NodeInfo.getNodeName())) {
          continue;
        }
        X500Name dname = null;
        try {
          dname = new X500Name(getX500DN(cname,
            trustedCaPolicy.getCertificateAttributesPolicy()));
        } catch (IOException iox) {}

        if (log.isDebugEnabled()) {
          log.debug("processing cert request for " + cname + " : " + dname);
        }

        checkOrMakeCert(dname, false, trustedCaPolicy);
      }
    }
  }

/*
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

*/
  /** Build a search filter for LDAP based on the distinguished name
   */
  public  String parseDN(String aDN)
    {
      String filter = "(&";

      StringTokenizer parser = new StringTokenizer(aDN, ",=");
      while(parser.hasMoreElements()) {
	String tok1 = parser.nextToken().trim().toLowerCase();
	if (tok1.equals("t"))
	  tok1 = "title";
	String tok2 = parser.nextToken();
	filter = filter + "(" + tok1 + "=" + tok2 + ")";
      }
      filter = filter + ")";
      if (log.isDebugEnabled()) {
	log.debug("Search filter is " + filter);
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
      PrivateKeyPKCS12 pkcs12Mgmt = new PrivateKeyPKCS12(this,
							 param.serviceBroker);

      String nodeName = NodeInfo.getNodeName();
      List signerCertificateList = findCert(nodeName);
      X509Certificate signerCertificate =
	((CertificateStatus)signerCertificateList.get(0)).getCertificate();

      List pkc = findPrivateKey(nodeName);
      // Take the first key to sign
      PrivateKey signerPrivKey = ((PrivateKeyCert)pkc.get(0)).getPrivateKey();

      List certList = findCert(agentCN);
      List privKeyList = findPrivateKey(agentCN);

      List rcvrCertList = findCert(rcvrNode);
      X509Certificate rcvrCert = ((CertificateStatus)rcvrCertList.get(0)).getCertificate();
      List rcvrPrivKeyList = findPrivateKey(rcvrNode);
      // Take the first key to encrypt
      PrivateKey rcvrPrivKey = ((PrivateKeyCert)(rcvrPrivKeyList.get(0))).getPrivateKey();

      byte[] pkcs12 = pkcs12Mgmt.protectPrivateKey(privKeyList,
						   certList,
						   signerPrivKey,
						   signerCertificate,
						   rcvrCert);
      return pkcs12;
    }

  public void installPkcs12Envelope(byte[] pfxBytes)
    {
      PrivateKeyPKCS12 pkcs12Mgmt = new PrivateKeyPKCS12(this,
							 param.serviceBroker);

      String nodeName = NodeInfo.getNodeName();

      List rcvrCertList = findCert(nodeName);
      List rcvrPrivKeyList = findPrivateKey(nodeName);

      PrivateKeyCert[] pkey = pkcs12Mgmt.getPfx(pfxBytes,
						rcvrPrivKeyList,
						rcvrCertList);
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
	  if (log.isWarnEnabled()) {
	    log.warn("Warning: Certificate cannot be trusted");
	  }
	  // Do not add to the list
	  continue;
	}

	CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												     CertificateCacheService.class,
												     null);
       
	if(cacheservice==null) {
	  log.warn("Unable to get Certificate cache Service in installPkcs12Envelope");
	}
	// Get the common name of that certificate
	String cn =null;
	if(cacheservice!=null) {
	  cn=cacheservice.getCommonName(cs.getCertificate());
	}

	// Get the next available alias for this key.
	String alias = getNextAlias( cn);

	// Set the key entry in the keystore.
	if(cacheservice!=null) {
	  cacheservice.setKeyEntry(alias, pk, certChain);
	}

	if (log.isDebugEnabled()) {
	  log.debug("installPkcs12Envelope: add Private Key");
	}
	if(cacheservice!=null) {
	  // Update the certificate cache
	  cacheservice.addCertificate(cs);
	
	  // Update private key cache
	  cacheservice.addPrivateKey(pk, cs);
	  // Update Common Name to DN hashtable
	  cacheservice.addNameToNameMapping(cs);
	}
	else {
	  log.warn("Unable to get Certificate cache service in installPkcs12Envelope..Cannot add certificate to certificate cache");
	}
      }
    }

  private String sendPKCS(String request, String pkcs, TrustedCaPolicy trustedCaPolicy) {
    String reply = "";

    if (log.isDebugEnabled()) {
      log.debug("Sending request to " + trustedCaPolicy.caURL
		+ ", DN= " + trustedCaPolicy.caDN);
    }

    if (trustedCaPolicy == null) {
      if (log.isErrorEnabled())
	log.error("No TrustedCaPolicy, cannot send PKCS!");
      return reply;
    }

    try {
      URL url = new URL(trustedCaPolicy.caURL);
      HttpURLConnection huc = (HttpURLConnection)url.openConnection();
      // Don't follow redirects automatically.
      huc.setInstanceFollowRedirects(false);
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
      String content = "pkcs=" + URLEncoder.encode(pkcs, "UTF-8");
      content = content + "&role=" + URLEncoder.encode(role, "UTF-8");
      content = content + "&dnname="
	+ URLEncoder.encode(trustedCaPolicy.caDN, "UTF-8");
      content = content + "&pkcsdata=" + URLEncoder.encode(request, "UTF-8");
      out.println(content);
      out.flush();
      out.close();

      BufferedReader in =
	new BufferedReader(new InputStreamReader(huc.getInputStream()));
      StringBuffer sbuf = new StringBuffer();
      int len = 2000;     // Size of a read operation
      char [] cbuf = new char[len];
      int read;
      while ((read = in.read(cbuf, 0, len)) > 0) {
	sbuf.append(cbuf,0,read);
      }
      in.close();
      reply = sbuf.toString();
      reply = URLDecoder.decode(reply, "UTF-8");
      if (log.isDebugEnabled()) {
	log.debug("Reply: " + reply);
      }

    } catch(Exception e) {
      log.warn("Unable to send PKCS request to CA. CA URL:" + trustedCaPolicy.caURL
	       + " . CA DN:" + trustedCaPolicy.caDN, e);
    }

    return reply;
  }

  private String signPKCS(String request, String nodeDN, TrustedCaPolicy trustedCaPolicy){
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try{
      if (log.isDebugEnabled()) {
	log.debug("Signing PKCS10 request with node");
      }
      CertificateManagementService km = (CertificateManagementService)
	param.serviceBroker.getService(new CertificateManagementServiceClientImpl(nodeDN),
				       CertificateManagementService.class,
				       null);
      X509Certificate[] cf =
	km.processPkcs10Request(new ByteArrayInputStream(request.getBytes()));
      PrintStream ps = new PrintStream(baos);
      CertificateUtility.base64EncodeCertificates(ps, cf);
      //get the output to the CA
      String req = baos.toString();
      String reply = sendPKCS(req, "PKCS7", trustedCaPolicy);
    } catch(Exception e) {
      log.warn("Can't get the certificate signed: "
	       + e.getMessage());
    }
    return baos.toString();
  }

 

  /*
    private void saveCertificateInTrustedKeyStore(X509Certificate aCertificate,
    String alias) {
    if (log.isDebugEnabled()) {
    log.debug("Setting CA keystore certificate entry:" + alias);
    }
    addCN2alias(alias, aCertificate);

    try {
    caKeystore.setCertificateEntry(alias, aCertificate);
    } catch(Exception e) {
    log.error("Unable to set certificate in the keystore - "
    + e.getMessage());
    }
    // Store key store in permanent storage.
    try {
    FileOutputStream out = new FileOutputStream(param.caKeystorePath);
    caKeystore.store(out, param.caKeystorePassword);
    out.flush();
    out.close();
    } catch(Exception e) {
    log.error("Can't flush the certificate to the keystore--"
    + e.getMessage());
    }
    }
  */
  

  private static final String CDTYPE_ATTR = "CertDirectoryType";
  private static final String CDURL_ATTR = "CertDirectoryURL";
  private static final String CERT_DIR = "/Certificates";

  public void updateNS(String commonName) {

    CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												 CertificateCacheService.class,
												 null);
  
    if(cacheservice==null){
      log.warn("Unable to get cache service in updateNS.. Will not be able to update "+
	       "x500name in namemapping:");

    }
    
    try {
      
      List nameList = null;
      if(cacheservice!=null) {
	nameList=cacheservice.getX500NameFromNameMapping(commonName);
      }
      if (nameList == null) {
	throw (new Exception("X500Name not found in name mapping"));
      }
      for (int i = 0; i < nameList.size(); i++) {
	updateNS((X500Name)nameList.get(i));
      }
    } catch (Exception ex) {
      log.warn("Unable to register LDAP URL to naming service for " + commonName + ". Reason:" + ex);
    }
  }

  /**
   * Adding LDAP URL entry in the naming service.
   */
  public void updateNS(X500Name x500Name) {
    // check whether cert exist and whether it is agent
    String dname = x500Name.toString();
    String title = CertificateUtility.findAttribute(dname, "t");
    CertificateCacheService cacheservice=(CertificateCacheService)
      param.serviceBroker.getService(this,
				     CertificateCacheService.class,
				     null);
    
    if(cacheservice==null) {
      log.warn("Unable to get Certificate cache Service in updateNS");
    }
    
    if (log.isDebugEnabled()) {
      log.debug("updateNS: " + dname);
    }
    if (title == null ||
	!(title.equals(CertificateCache.CERT_TITLE_AGENT) ||
	  title.equals(CertificateCache.CERT_TITLE_NODE) ||
	  title.equals(CertificateCache.CERT_TITLE_SERVER))) {
      log.info("Not registering LDAP URL to naming service. Wrong title. DN:" + dname);
      return;
    }
    List certificateList = findCert(x500Name);
    if (certificateList == null || certificateList.size() == 0) {
      log.warn("Not registering LDAP URL to naming service. Cannot find certificate. DN:" + dname);
      return;
    }
    try {
      DirContext ctx = ensureCertContext();
      String cname = x500Name.getCommonName();

      BasicAttributes attributes = null;
      try {
	attributes = (BasicAttributes) getNamingAttributes(cname);
      } catch (NamingException nex) {}
      if (attributes == null) {
	attributes = new BasicAttributes();
      }
      /*
	if (title.equals(CERT_TITLE_AGENT) ||
	title.equals(CERT_TITLE_NODE) ||
	title.equals(CERT_TITLE_SERVER)) {
	attributes.put(CDTYPE_ATTR, new Integer(param.ldapServerType));
	attributes.put(CDURL_ATTR, param.ldapServerUrl);
	}
	// for CA should put the ca policy LDAP
	else if(title.equals(CERT_TITLE_CA)) {
	CaPolicy caPolicy = configParser.getCaPolicy(dname);
	attributes.put(CDTYPE_ATTR, new Integer(caPolicy.ldapType));
	attributes.put(CDURL_ATTR, caPolicy.ldapURL);
	}
	else {
	log.info("Unable to register LDAP URL for " + dname + ". Wrong title");
	}
      */

      // go get the CA dn to find out who signed the cert
      X500Name x500Principal = x500Name;
      String ldapUrl = param.ldapServerUrl;
      int ldapType = param.ldapServerType;
      TrustedCaPolicy [] tc = cryptoClientPolicy.getIssuerPolicy();
      if (tc.length > 1) {
	while (true) {
	  List certList = null;
	  //if(cacheservice!=null) {
	  certList=getValidCertificates(x500Principal);
	  //}
	  if (certList == null || certList.size() == 0) {
	    break;
	  }

	  CertificateStatus cs = (CertificateStatus)certList.get(0);
	  X509Certificate certificate = (X509Certificate)cs.getCertificate();
	  x500Principal = CertificateUtility.getX500Name(certificate.getIssuerDN().getName());
	  // if it is not the node it must be the signing CA
	  String commonname=null;
	  if(cacheservice!=null) {
	    commonname=cacheservice.getCommonName(x500Principal);
	  }
	  if (!(commonname!=null &&commonname.equals(NodeInfo.getNodeName()))) {
	    for (int i = 1; i < tc.length; i++) {
	      if (tc[i].caDN.equals(x500Principal.getName())) {
		ldapUrl = tc[i].certDirectoryUrl;
		ldapType = tc[i].certDirectoryType;
	      }
	    }
	    break;
	  }
	}
      }

      BasicAttributes ldapattrib = new BasicAttributes();
      ldapattrib.put(CDTYPE_ATTR, new Integer(ldapType));
      ldapattrib.put(CDURL_ATTR, ldapUrl);

      attributes.put(x500Name.getName(), ldapattrib);
      String value = cname.toLowerCase();
      ctx.rebind(value, value, attributes);

      if (log.isDebugEnabled()) {
	log.debug("successfully update: " + value + " attrib: " + attributes + " in NS");
      }

    } catch (Exception nx) {
      if (log.isWarnEnabled()) {
	log.warn("Cannot update "+dname+ " ldap in naming." + nx.toString(), nx);
      }
    }

    //log.warn("Cannot update agent ldap in naming.");
  }

  /** Retrieve the certificate directory service associated with a specified CA.
   *  A node running as a certificate authority can support multiple CA keys.
   *  Each CA has its own LDAP server.
   */
  public CertDirectoryServiceClient getCACertDirServiceClient(String dname) {
    TrustedCaPolicy[] tc = cryptoClientPolicy.getTrustedCaPolicy();
    if (log.isDebugEnabled()) {
      log.debug("get trusted CA ldap for " + dname);
    }
    for (int i = 0; i < tc.length; i++) {
      if (dname.equals(tc[i].caDN)) {
	if (log.isDebugEnabled()) {
	  log.debug("Using " + tc[i].caURL + " for ldap - " + tc[i].certDirectoryUrl);
	}

	CertDirectoryServiceRequestor cdsr =
	  new CertDirectoryServiceRequestorImpl(tc[i].certDirectoryUrl, tc[i].certDirectoryType,
						param.serviceBroker, tc[i].caDN);
	CertDirectoryServiceClient cf = (CertDirectoryServiceClient)
	  param.serviceBroker.getService(cdsr, CertDirectoryServiceClient.class, null);
	return cf;
      }
    }
    return null;
  }

  /**
   * get information from naming service, input is common name.
   * Only agent information is registered with ldap naming.
   */
  public BasicAttributes getNamingAttributes(String cname)
    throws NamingException  {

    String key = cname.toLowerCase();
    BasicAttributes attrs =
      (BasicAttributes) _namingAttributesCache.get(key);
    if (attrs == null) {
      DirContext ctx = ensureCertContext();
      attrs = (BasicAttributes) ctx.getAttributes(key);
      if (attrs != null) {
	_namingAttributesCache.put(key,attrs);
      }
    }
    return attrs;
  }

  /**
   * Return an LDAP certificate directory where the X.509 certificate of the entity can be found.
   * A Cougaar society can include multiple Certificate Authorities.
   * When two agents A and B communicate, their certificates may not have been signed by the same CA.
   * Therefore, the certificates may be in two different certificate directory services.
   * When A wants to communicate with B, it needs to:
   *  1) Find the certificate directory where it can find B's certificate.
   *  2) Lookup B's certificate in that certificate directory.
   * Step 1 is performed by looking up the LDAP url in the naming service. The LDAP url is in the
   * naming service because B has registered the URL of its certificate directory service when
   * B was started.
   */
  public CertDirectoryServiceClient getCertDirectoryServiceClient(X500Name dname) {
    if (log.isDebugEnabled()) {
      log.debug("Looking up certificate finder for " + dname);
    }

    // no need for naming service for CA
    if (param.isCertAuth) {
      return certificateFinder;
    }
    CertificateCacheService cacheservice=(CertificateCacheService)
      param.serviceBroker.getService(this,
				     CertificateCacheService.class,
				     null);
     
    if(cacheservice==null) {
      log.warn("Unable to get Certificate cache Service in getCertDirectoryServiceClient");
    }

    String cdUrl = null;
    String cname = null;
    if(cacheservice!=null) {
      cname=cacheservice.getCommonName(dname);
    }
    if ((cname!=null &&cname.equals(NodeInfo.getNodeName())) || 
	(cname!=null && cname.equals(NodeInfo.getHostName()))) {
      if (log.isDebugEnabled()) {
	log.debug("Returning default certificateFinder:" + certificateFinder);
      }
      return certificateFinder;
    }

    try {
      BasicAttributes ldapattrib = getNamingAttributes(cname);
      BasicAttributes attrib = null;
      if (ldapattrib != null) {
	attrib = (BasicAttributes)getAttribute(ldapattrib, dname.getName());

	if (attrib != null) {
	  if (log.isDebugEnabled()) {
	    log.debug("getCertDirectoryServiceClient: " + dname + " attrib: "
		      + attrib);
	  }
	  Integer cdType = (Integer)getAttribute(attrib, CDTYPE_ATTR);
	  cdUrl = (String)getAttribute(attrib, CDURL_ATTR);
	  if (cdType != null && cdUrl != null) {

	    CertDirectoryServiceRequestor cdsr =
	      new CertDirectoryServiceRequestorImpl(cdUrl, cdType.intValue(),
						    param.serviceBroker, param.defaultCaDn);
	    CertDirectoryServiceClient cdsc = (CertDirectoryServiceClient)
	      param.serviceBroker.getService(cdsr, CertDirectoryServiceClient.class, null);
	    return cdsc;
	  }
	}
      }
      if (attrib == null) {
	if (log.isInfoEnabled()) {
	  log.info("Unable to find attributes in NS for " + dname + ". Will retry later.");
	}
      }
    } catch (Exception nx) {
      if (!(nx instanceof NamingException)) {
	if (log.isWarnEnabled())
	  log.warn("Cannot get LDAP lookup service at " + cdUrl + ". Reason:"
		   + nx.toString(), nx);
      }
      else {
	// We are trying to lookup an agent's certificate, but the agent
	// hasn't registered yet in the naming service.
	if (log.isInfoEnabled())
	  log.info("Unable to get certificate finder for " + cname + ". Reason:" + nx
		   + ". Returning default certificate Finder");
      }
    }
    // default
    return certificateFinder;
  }

  private DirContext ensureCertContext()
    throws NamingException {
    // First, get the Naming service root context
    if (namingContext != null) {
      return namingContext;
    }

    NamingService namingSrv = (NamingService)
      param.serviceBroker.getService(this,
				     NamingService.class,
				     null);

    if (namingSrv == null) {
      throw new NamingException("Cannot get naming service");
    }

    DirContext ctx = namingSrv.getRootContext();
    try {
      // Try to to get the /Certificate subcontext
      try {
	ctx = (DirContext) ctx.lookup(CERT_DIR);
      } catch (NamingException ne) {
	// If nobody has registered yet for the /Certificate subcontext,
	// create it.
	if (log.isInfoEnabled()) {
	  log.info("Creating " + CERT_DIR + " subcontext in the naming service");
	}
	try {
	  ctx = (DirContext)
	    ctx.createSubcontext(CERT_DIR, new BasicAttributes());
	} catch (NameAlreadyBoundException nbex) {
	  // concurrency issue, context may be created already
	  ctx = (DirContext) ctx.lookup(CERT_DIR);
	}
      }
    } catch (Exception e) {
      NamingException x = new NamingException("Unable to access name-server");
      x.setRootCause(e);
      if (log.isWarnEnabled()) {
	log.warn(x.getMessage());
      }
      throw x;
    }
    namingContext = ctx;

    return ctx;
  }

  private Object getAttribute(BasicAttributes ats, String id) throws NamingException {
    if (ats != null) {
      Attribute at = ats.get(id);
      if (at != null) {
	return at.get();
      }
    }
    return null;
  }

  public boolean checkExpiry(String commonName) {
    boolean expired = false;
    TrustedCaPolicy [] tc = cryptoClientPolicy.getIssuerPolicy();
    if (tc.length == 0) {
      // root CA
      expired = checkExpiry(commonName, null);
    }
    else {
      for (int i = 0; i < tc.length; i++) {
	if (checkExpiry(commonName, tc[i]) && !expired)
	  expired = true;
      }
    }
    return expired;
  }

  private boolean checkExpiry(String commonName, TrustedCaPolicy trustedCaPolicy) {
    CertificateAttributesPolicy certAttribPolicy =
      cryptoClientPolicy.getCertificateAttributesPolicy(trustedCaPolicy);
    List certificateList = findCert(CertificateUtility.getX500Name(getX500DN(commonName, certAttribPolicy)));
    if(certificateList != null && certificateList.size() != 0) {
      // check envelope
      long envelope = certAttribPolicy.regenEnvelope;
      CertificateStatus cs = (CertificateStatus)certificateList.get(0);

      Date notafter = cs.getCertificate().getNotAfter();
      Date curdate = new Date();
      if (log.isDebugEnabled())
	log.debug("Alias: " + cs.getCertificateAlias() + ", Envelope: " + envelope + " ? " + curdate + " : " + notafter);
      if (curdate.getTime() + envelope * 1000L < notafter.getTime()) {
	// maybe upper level has expired
	try {
	  checkCertificateTrust(cs.getCertificate());
	  return true;
	} catch (CertificateException cex) {
	  // do not handle certificate revoked exception, should just fail to verify
	  // because cannot establish chain (cannot find valid cert)
	  if (log.isDebugEnabled())
	    log.debug("checkCertificateTrust: " + cex);
	  if (!(cex instanceof CertificateExpiredException))
	    return false;
	}

      }

    }
    // expired, regen key
    if (log.isDebugEnabled())
      log.debug("Certificate expired, requesting again.");

    // TODO: get the certificate that is expiring, get the trusted CA
    // from signer, then find the TrustedCaPolicy.
    addKeyPair(commonName, null, trustedCaPolicy);
    // Problem: If a certificate has been revoked, the CA should not regenerate a certificate
    // automatically. However, this is what the CA is doing right now.
    // In the checkExpiry method, we call findCert() first, which returns null if the certificate
    // has been revoked. The method would then re-issue a new certificate, and a new
    // valid certificate would be generated.
    // For now, the code is commented out as a workaround, but this should be fixed.

    return true;
  }

  /**
   * Search NS, find matching cert pair for source and target with the right
   * trust.
   * Return: Hashtable with cert or cert path found, source and target are
   *          the keys.
   * Note: to be efficient, the result pair should be cached. Since
   *         CryptoManagerServiceImpl is already caching the result,
   *         there is no need to cache the result here.
   */
  public Hashtable findCertPairFromNS(String source, String target)
    throws CertificateException
    {
      // check whether agent has started yet, this fixes the problem where
      // LDAP is dirty and returning old certificates. If agent has started
      // and obtained new certificates it will update naming.
      if (log.isDebugEnabled()) {
	log.debug("findCertPairFromNS: " + source + " vs " + target);
      }

      Hashtable certTable = new Hashtable();

      List srcdns = findDNFromNS(target);
      List tgtdns = findDNFromNS(target);
      if (tgtdns.size() == 0 || srcdns.size() == 0) {
	if (log.isDebugEnabled()) {
	  log.debug("Failed to get naming attributes: " + source + " vs " + target);
	}
	return certTable;
      }

      // find if there is a path in target that is trusted
      // TODO: if there is multiple trusted path choose the shortest one

      // how deep is the trusted cert
      X509Certificate [] tgtCerts = null;
      int trustedIndex = 1000;
      TrustedCaPolicy [] tc = cryptoClientPolicy.getTrustedCaPolicy();
      Hashtable tcTable = new Hashtable();
      for (int i = 0; i < tc.length; i++) {
	tcTable.put(tc[i].caDN, tc[i].caDN);
      }

      Iterator it = tgtdns.iterator();
      while (it.hasNext()) {
	X500Name dname = (X500Name)it.next();
	List tgtList = findCert(dname,
				KeyRingService.LOOKUP_KEYSTORE | KeyRingService.LOOKUP_LDAP, true);
	if (tgtList != null && tgtList.size() != 0) {
	  // this should not have certificate exception because the cert
	  // path is supposed to be established and valid
	  CertificateStatus cs = (CertificateStatus)tgtList.get(0);
	  // chain should be valid because findCert has been called
	  tgtCerts = checkCertificateTrust((X509Certificate)cs.getCertificate());
	  for (int i = 1; i < tgtCerts.length && i < trustedIndex; i++) {
	    String principalName = tgtCerts[i].getSubjectDN().getName();
	    if (tcTable.get(principalName) != null) {
	      trustedIndex = i;
	    }
	  }

	  // there must be one that matches, otherwise check trust is not correct
	  certTable.put(target, tgtCerts[0]);
	}
      }

      // find the matching source path
      if (certTable.get(target) == null) {
	String errMsg = "No trusted path found for " + target;
	if (log.isDebugEnabled()) {
	  log.debug(errMsg);
	}
	throw new CertificateException(errMsg);
      }
      String trustedPrincipal = tgtCerts[trustedIndex].getSubjectDN().getName();
      if (log.isDebugEnabled()) {
	log.debug("Found trusted cert : " + certTable.get(target) + " for " + target
		  + ", the shortest path to trusted ca: " + trustedPrincipal);
      }

      X509Certificate [] srcCerts = null;
      boolean found = false;
      it = srcdns.iterator();
      while (it.hasNext() && !found) {
	X500Name dname = (X500Name)it.next();
	List srcList = findCert(dname,
				KeyRingService.LOOKUP_KEYSTORE | KeyRingService.LOOKUP_LDAP, true);
	if (srcList != null && srcList.size() != 0) {
	  CertificateStatus cs = (CertificateStatus)srcList.get(0);
	  // the trust chain should be valid
	  srcCerts = checkCertificateTrust((X509Certificate)cs.getCertificate());

	  // we can communicate now, put a cert that is trusted by both sides here
	  // if we find a cert that has the shortest path to target then replace
	  // the hashtable entry with that one
	  certTable.put(source, srcCerts[0]);

	  for (int i = 1; i < srcCerts.length; i++) {
	    // principal matched?
	    if (trustedPrincipal.equals(srcCerts[i].getSubjectDN().getName())) {
	      certTable.put(source, srcCerts[0]);
	      found = true;
	    }
	  }
	}
      }

      // is it successful?
      if (!found) {
	String errMsg = "Can not find matching source cert with same trust.";
	if (log.isDebugEnabled()) {
	  log.debug(errMsg);
	}
	throw new CertificateException(errMsg);
      }

      if (log.isDebugEnabled()) {
	log.debug("Found trusted cert : " + certTable.get(source) + " for " + source);
      }
      if (!found) {
	if (log.isWarnEnabled()) {
	  log.warn("No cert of " + source + " signed by " +
		   trustedPrincipal + " has been found.");
	}
      }

      return certTable;
    }

  public List findDNFromNS(String name) {
    List nameList = new ArrayList();
    try {
      BasicAttributes ldapattrib = getNamingAttributes(name);
      if (ldapattrib != null) {
	NamingEnumeration ids = ldapattrib.getIDs();
	while (ids.hasMore()) {
	  X500Name dname = CertificateUtility.getX500Name((String)ids.next());
	  nameList.add(dname);
	}
      }
      else {
	if (log.isDebugEnabled()) {
	  log.debug("No ldap attrib found in naming for " + name
		    + ". It may not have been started yet.");
	}
      }
    }
    catch (NamingException ns) {
      if (log.isDebugEnabled()) {
	log.debug("findCertFromNS failed, reason: " + ns);
      }
    }

    return nameList;
  }

  private class CertificateManagementServiceClientImpl
    implements CertificateManagementServiceClient
  {
    private String caDN;
    public CertificateManagementServiceClientImpl(String aCaDN) {
      caDN = aCaDN;
    }
    public String getCaDN() {
      return caDN;
    }
  }
/*
  public CertificateAttributesPolicy getDefaultCertAttrPolicy() {
  TrustedCaPolicy [] tc = cryptoClientPolicy.getIssuerPolicy();
  if (tc.length == 0) {
  return cryptoClientPolicy.getCertificateAttributesPolicy();
  }
  return cryptoClientPolicy.getCertificateAttributesPolicy(tc[0]);
  }
*/

  public String getX500DN(String commonName) {
    return getX500DN(commonName, cryptoClientPolicy.getCertificateAttributesPolicy());
  }

  public static String getX500DN(String commonName, CertificateAttributesPolicy certAttribPolicy) {
    String dn = "cn=" + commonName
      + ", ou=" + certAttribPolicy.ou
      + ",o=" + certAttribPolicy.o
      + ",l=" + certAttribPolicy.l
      + ",st=" + certAttribPolicy.st
      + ",c=" + certAttribPolicy.c
      + ",t=" + CertificateCache.getTitle(commonName);
    return dn;
  }

  public String findAlias(String commonName) {
    CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												 CertificateCacheService.class,
												 null);
    if(cacheservice==null) {
      log.warn(" Unabale to get Certificate cache service in findAlias"); 
    }
    return cacheservice.findAlias(CertificateUtility.getX500Name(getX500DN(commonName)));
  }

  public void setKeyEntry(PrivateKey key, X509Certificate cert) {
      
    CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												 CertificateCacheService.class,
												 null);
    if(cacheservice==null) {
      log.warn(" Unabale to get Certificate cache service in setKeyEntry"); 
    }
      
    if (log.isDebugEnabled()) {
      log.debug("setKeyEntry for " + cert.toString());
    }
    X509Certificate[] certificateChain = null;
    try {
      certificateChain = checkCertificateTrust(cert);
    }
    catch (Exception e) {
      if (log.isErrorEnabled()) {
	log.error("Unable to setKeyEntry: " + e);
      }
    }
    if (certificateChain != null) {
      String alias = null;
      X500Name dname = CertificateUtility.getX500Name(cert.getSubjectDN().getName());
      String commonName = null;
      CertificateStatus cs =null;
      if(cacheservice!=null) {
	commonName=cacheservice.getCommonName(dname);
	alias = getNextAlias(commonName);
	cacheservice.setKeyEntry(alias, key, certificateChain);
	// Updating certificate cache
	cs = cacheservice.addKeyToCache(cert, key, alias, CertificateType.CERT_TYPE_END_ENTITY);
	// Update the certificate trust
	cacheservice.setCertificateTrust(cert, cs, dname, null);
      }
    }
    else {
      log.warn("Certificate chain is null");
    }
  }

  public void removeEntry(String commonName)
    {
      if (log.isInfoEnabled()) {
	log.info("Removing entry from keystore:" + commonName);
      }

      String alias = findAlias(commonName);
      CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
												   CertificateCacheService.class,
												   null);
      if(cacheservice==null) {
	log.warn(" Unabale to get Certificate cache service in removeEntry"); 
      }
      if(cacheservice!=null){
	cacheservice.deleteEntry(alias, commonName);
      }

      //certCache.deleteCertificate();
      //certCache.deletePrivateKey();

      if (log.isDebugEnabled()) {
	if(cacheservice!=null){
	  cacheservice.printCertificateCache();
	}
      }

      // TODO: for node, hostname, CA aliases, need to get replacement
    }
  private boolean checkCertificate(CertificateStatus cs) {
    return checkCertificate(cs, false, false);
  }

  /** Check the certificate validity of a certificate.
   */
  public boolean checkCertificate(CertificateStatus cs,
				  boolean buildChain, boolean changeStatus) {
    boolean isTrustedAndValid = false;

    // What is this for? If not important for every find then
    // put it in operations performed during background thread
    if (buildChain) {
      X500Name x500Name = null;
      try {
        x500Name = new X500Name(cs.getCertificate().getSubjectDN().getName());
      } catch(Exception e) {
        if (log.isWarnEnabled()) {
          log.warn("Unable to get X500 Name - " + e);
        }
      }
    }

    // The first element in the list should be the most up-to-date
    // certificate. However, there are some cases where it may not.
    // For instance, we may have just received a new certificate from the CA,
    // but it is not yet valid and we still have another certificate
    // which is still valid.
    if (cs == null) {
      throw new IllegalArgumentException("CertificateStatus is null");
    }
    try {
      cs.checkCertificateValidity();

      if (buildChain)
        checkCertificateTrust(cs.getCertificate());
      // Certificate is valid. Return it.
      isTrustedAndValid = true;
    }
    catch (CertificateNotTrustedException e) {
      // Find out cause
      if (e.cause == CertificateTrust.CERT_TRUST_SELF_SIGNED) {
	/* Certificate has not been signed by a CA. Either the CA has refused
	 * to issue the certificate or communication with the CA was not
	 * possible. */

	/* There are two cases:
	 * 1) If this is a remote entity certificate, then we need to send
	 * a message to that remote entity, notifying that the certificate
	 * cannot be trusted. The remote entity will then have to request
	 * an appropriate certificate and have the CA publish it to the
	 * certificate directory.
	 * This capability has yet to be implemented (TODO).
	 *
	 * 2) If this a local entity certificate, then we can send a certificate
	 * signing request to the CA. If the certificate has a matching private key,
	 * then it is considered a local entity.
	 */
	if (log.isDebugEnabled()) {
	  log.debug("checkCertificate. Certificate is self-signed");
	}
      }
      else if (e.cause == CertificateTrust.CERT_TRUST_UNKNOWN) {
	// Try to find out certificate trust
	if (log.isDebugEnabled()) {
	  log.debug("checkCertificate. Certificate trust is unknown");
	}
	isTrustedAndValid = false;
      }
      else {
	// Otherwise, certificate is not trusted.
	if (log.isWarnEnabled()) {
	  log.warn("checkCertificate. Not trusted. Cause="
		   + e.cause);
	}
	isTrustedAndValid = false;
      }
      // TODO: mechanism by which one can send a message to a remote entity
      // requesting for that entity to generate a certificate that we can use.
    }
    catch (CertificateException e) {
      // There is no suitable private key (expired, revoked, ...)
      // Request a new one to the Certificate Authority
      if (log.isInfoEnabled()) {
	log.info("Invalid certificate: " + e);
      }

      // in some cases (cert chain problem) the status should be changed
      // otherwise next time if chain verification is not specified the
      // cert will still be considered valid
      // this code only handles revoked cert, should change status anytime
      // on any certificate
      if (changeStatus) {
        if (e instanceof CertificateChainException) {
          if (log.isWarnEnabled()) {
            log.warn("One of signers in chain has been revoked.");
          }
          cs.setCertificateTrust( CertificateTrust. CERT_TRUST_REVOKED_CERT);
          cs.setValidity(false);
        }
      }

    }
    return isTrustedAndValid;
  }
  
  public List getValidCertificates(X500Name x500Name)
    {
      CertificateCacheService cacheservice=(CertificateCacheService)
	param.serviceBroker.getService(this,
				       CertificateCacheService.class,
				       null);
      if(cacheservice==null) {
	log.warn("CertificateCacheService is null in getValidCertificates");
	return null;
      }
       
      
      List allCertificates = cacheservice.getCertificates(x500Name);
      if (allCertificates == null || allCertificates.size() == 0) {
	return null;
      }

      List validCerts = Collections.synchronizedList(new ArrayList());
      // return the cert with the longest notafter day first
      // most modules will use the cert
      long notafter = 0L;

      synchronized(allCertificates) {
	ListIterator it = allCertificates.listIterator();
	while (it.hasNext()) {
	  CertificateStatus cs = (CertificateStatus) it.next();
	  boolean isTrustedAndValid = checkCertificate(cs);
	  if (isTrustedAndValid) {
	    long certtime = cs.getCertificate().getNotAfter().getTime();
	    if (certtime > notafter) {
	      notafter = certtime;
	      validCerts.add(0, cs);
	    }
	    else {
	      validCerts.add(cs);
	    }
	  }
	}
      }
      return validCerts;
    }
  
  public List getValidPrivateKeys(X500Name x500Name) {
    CertificateCacheService cacheservice=(CertificateCacheService)
      param.serviceBroker.getService(this,
				     CertificateCacheService.class,
				     null);
    if(cacheservice==null) {
      log.warn("CertificateCacheService is null in getValidPrivateKeys");
      return null;
    }
     
    List allCertificates = cacheservice.getPrivateKeys(x500Name);
    if (allCertificates == null || allCertificates.size() == 0) {
      if (log.isDebugEnabled()) {
	log.debug("No private key for " + x500Name);
      }
      return null;
    }
    List validPrivateKeys = Collections.synchronizedList(new ArrayList());

    synchronized(allCertificates) {
      ListIterator it = allCertificates.listIterator();
      while (it.hasNext()) {
	PrivateKeyCert cs = (PrivateKeyCert) it.next();
	boolean isTrustedAndValid = checkCertificate(cs.getCertificateStatus());
	if (log.isDebugEnabled()) {
	  log.debug("Checking certificate trust: " + cs.getCertificateStatus()
		    + ". Trust: " + isTrustedAndValid);
	}
	if (isTrustedAndValid) {
	  validPrivateKeys.add(cs);
	}
      }
    }
    return validPrivateKeys;
  }

  public boolean setCertificateTrust(X509Certificate certificate, CertificateStatus cs,
				     X500Name name, Hashtable selfsignedCAs) {
    boolean isTrusted = false; // Raise a warning if there is no trusted cert for that entity.
    /*KeyRingService ks =  (KeyRingService)serviceBroker.getService(this,
      KeyRingService.class,
      null);
      if(ks==null) {
      return isTrusted;
      }
    */
    CertificateCacheService caches =  (CertificateCacheService)
      param.serviceBroker.getService(this,
				     CertificateCacheService.class,
				     null);
    try {
      X509Certificate[] certs = checkCertificateTrust(certificate);
      // Could establish a certificate chain. Certificate is trusted.
      // Update Certificate Status.
      if (log.isDebugEnabled()) {
        log.debug("Certificate chain established for " + certificate.getSubjectDN().getName());
      }
      cs.setCertificateTrust(CertificateTrust.CERT_TRUST_CA_SIGNED);
      if(caches!=null){
	caches.updateBigInt2Dn(certificate, true);
      }
      isTrusted = true;
    }
    catch (CertificateChainException exp) {
      if (log.isInfoEnabled()) {
	log.info("Unable to get certificate chain. Cause= "
		 + exp.cause + " - Cert:" + certificate.toString());
      }
      if (exp.cause == CertificateTrust.CERT_TRUST_SELF_SIGNED) {
	// Maybe we didn't get a reply from the CA the last time
	// we created the certificate. Send a new PKCS10 request to the CA.
	cs.setCertificateTrust(CertificateTrust.CERT_TRUST_SELF_SIGNED);

	// is CA certificate created but pending?
	if (!cryptoClientPolicy.isRootCA() && param.isCertAuth) {
	  // We are a subordinate CA
	  if (cs.getCertificateType() == CertificateType.CERT_TYPE_CA) {
	    // should this be moved to after initialization?
            String cn = caches.getCommonName(name);
            selfsignedCAs.put(cn, cn);
	  }
	}
      }
    }
    catch (CertificateExpiredException exp) {
      if (log.isInfoEnabled()) {
	log.info("Certificate in chain has expired. "
		 + " - " + exp);
      }
    }
    catch (CertificateNotYetValidException exp) {
      if (log.isInfoEnabled()) {
	log.info("Certificate in chain is not yet valid. "
		 + " - " + exp);
      }
    }
    catch(CertificateRevokedException certrevoked) {
      if(log.isInfoEnabled()) {
	log.info(" certificate is revoked for dn ="
		 +((X509Certificate)certificate).getSubjectDN().getName());
      }
    }
    return isTrusted;
  }

  /*
    public Enumeration getAliasList() {
    CertificateCacheService cacheservice=(CertificateCacheService)
    param.serviceBroker.getService(this,
    CertificateCacheService.class,
    null);
    Enumeration list=null;
    if(cacheservice==null) {
    log.warn(" Unabale to get Certificate cache service in removeEntry"); 
    return list;
    }
    list=cacheservice.getAliasList();
    return list;
    }
    public  String getCommonName(String alias){
    String commonname=null;
    CertificateCacheService cacheservice=(CertificateCacheService)param.serviceBroker.getService(this,
    CertificateCacheService.class,
    null);
    if(cacheservice==null) {
    log.warn(" Unabale to get Certificate cache service in removeEntry"); 
    return commonname;
      
    }
    commonname=cacheservice.getCommonName(alias);
    return commonname;
    }

    public void removeEntryFromCache(String commonName){
    CertificateCacheService cacheservice=(CertificateCacheService)
    param.serviceBroker.getService(this,
    CertificateCacheService.class,
    null);
    if(cacheservice==null) {
    log.warn(" Unabale to get Certificate cache service in removeEntryFromCache"); 
    return ;
    }
    cacheservice.removeEntryFromCache(commonName);
    }
  */

}


  
