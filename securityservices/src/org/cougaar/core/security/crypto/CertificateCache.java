/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.blackboard.SubscriberException;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.crypto.blackboard.InUseDNObject;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.services.crypto.CRLCacheService;
import org.cougaar.core.security.services.crypto.CertValidityService;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.ssl.KeyRingSSLFactory;
import org.cougaar.core.security.ssl.KeyRingSSLServerFactory;
import org.cougaar.core.security.ssl.TrustManager;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.AlarmService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.EventService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.util.ConfigFinder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;

import sun.security.x509.X500Name;

/** A hash table to store certificates from keystore, caKeystore and
 * the LDAP directory service, indexed by distinguished name.
 * Each entry in the hash table contains a list of all the certificates
 * for a given distinguished name.
 * The most up-to-date certificate is always the first element of the list.
 * The list is maintained by applying the following rules (from the end
 * of the list):
 * 1) Revoked certificates are pushed to the very end of the list.
 * 2) Expired certificates are next.
 * 3) Certificates which are not yet valid are next.
 * 4) For remaining certificates, certificates are sorted by most recently
 *    issued certificate first.
 */

final public class CertificateCache implements CertificateCacheService, BlackboardClient  {

  /** A hashtable that contains a cache of all the certificates (including valid and non valid certs)
   *  The hashtable key is a Principal.
   *  The hashtable value is a List of CertificateStatus
   */
  private Hashtable certsCache = new Hashtable(50);
  
  /** A hashtable that contains a cache of all the private keys (including valid and non valid private keys)
   *  The hashtable key is a Principal.
   *  The hashtable value is a List of PrivateKeyCert (which contains CertificateStatus and PrivateKey)
   */
  private Hashtable privateKeyCache = new Hashtable(50);

  /** definition for title field of certificate */

  public final static String CERT_TITLE_NODE = "node";
  public final static String CERT_TITLE_AGENT = "agent";
  public final static String CERT_TITLE_USER = "user";
  public final static String CERT_TITLE_SERVER = "server";
  public final static String CERT_TITLE_CA = "ca";


  private Hashtable bigint2dn=new Hashtable(50);
  private DirectoryKeyStoreParameters param;
  private SecurityPropertiesService secprop = null;
  private ServiceBroker serviceBroker;
  private ConfigParserService configParser = null;
  private NodeConfiguration nodeConfiguration;
  private LoggingService log;
  private KeyStore keystore = null;
  /** This keystore stores certificates of trusted certificate authorities. */
  private KeyStore caKeystore = null; 
  /** A hash map to quickly find an alias given a common name */
  private HashMap commonName2alias = new HashMap(89);
  /** A mapping between Cougaar name and distinguished names
   */
  private NameMapping nameMapping;
  private CryptoClientPolicy cachecryptoClientPolicy;
  private MyServiceAvailableListener serviceAvailableListener =null;
  private CRLCacheService _crlCacheService;
  protected String blackboardClientName;
  private BlackboardService _blackboardService=null;
  private AlarmService _alarmService =null;
  private ThreadService _threadService=null;
  private boolean initPublishDN=false;
  private EventService   _eventService;
  private MessageAddress myAddress;
   
/** Cache to store strings containing revoked certificate DN, issuer DN, and serial number,
 * The certificate being revoked may not be in cert cache.
 */
  private Hashtable revokedCache = new Hashtable();

  private ArrayList trustListeners = new ArrayList();

  public CertificateCache(ServiceBroker sb) {
    serviceBroker = sb;
    init();
  }

  private void init() {

    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class,
			       null);
    
    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class,
			       null);
    configParser = (ConfigParserService)
      serviceBroker.getService(this,
			       ConfigParserService.class,
			       null);
    nameMapping = new NameMapping(serviceBroker);
    _alarmService= (AlarmService)serviceBroker.getService(this,
                                                          AlarmService.class,
                                                          null);
    _threadService= (ThreadService)serviceBroker.getService(this,
                                                            ThreadService.class,
                                                            null);
    _blackboardService = (BlackboardService)serviceBroker.getService(this,
                                                                     BlackboardService.class,
                                                                     null);
    if(_blackboardService == null) {
      if(log.isDebugEnabled()) {
        log.debug(" BB Service is NULL in int of Certificate cache :");
      }
    }
    _crlCacheService = (CRLCacheService)serviceBroker.getService(this,
                                                                 CRLCacheService.class,
                                                                 null);
    _eventService = (EventService)serviceBroker.getService(this,
                                                           EventService.class,
                                                           null);
    AgentIdentificationService ais = (AgentIdentificationService)
      serviceBroker.getService(this, AgentIdentificationService.class, null);
    if (ais != null) {
      myAddress = ais.getMessageAddress();
      serviceBroker.releaseService(this, AgentIdentificationService.class,
                                   ais);
    }
    
    if(((_crlCacheService==null) || (_blackboardService==null) || 
        (_threadService==null)   || (_eventService == null)) &&
       (serviceAvailableListener==null)) {
      serviceAvailableListener=new MyServiceAvailableListener();
      serviceBroker.addServiceListener(serviceAvailableListener);
    }
        
    if (secprop == null) {
      throw new RuntimeException("unable to get security properties service");
    }
    if (configParser == null) {
      throw new RuntimeException("unable to get config parser service");
    }

    String installpath = secprop.getProperty(secprop.COUGAAR_INSTALL_PATH);
    
    String role =
      secprop.getProperty(secprop.SECURITY_ROLE);

    if (role == null && log.isInfoEnabled() == true) {
      if (log.isInfoEnabled()) {
	log.info("Role is not defined");
      }
    }

    if (log.isInfoEnabled()) {
      log.info(" Certificate Cache initilization called : ");
    }
    
    SecurityPolicy[] sp =
      configParser.getSecurityPolicies(CryptoClientPolicy.class);

    cachecryptoClientPolicy = (CryptoClientPolicy) sp[0];
    if(cachecryptoClientPolicy==null) {
      log.error(" cryptoClientPolicy is null in init of certificate cache :");
    }
    else {
      if (log.isInfoEnabled()) {
	log.info(" cryptoClientPolicy ----->"
		 + cachecryptoClientPolicy.toString());
      }
    }
    
    if (cachecryptoClientPolicy == null
	|| cachecryptoClientPolicy.getCertificateAttributesPolicy() == null) {
      
      // This is OK for standalone applications if they don't plan to use
      // certificates for authentication, but it's not OK for nodes
      boolean exec =
	Boolean.valueOf(System.getProperty("org.cougaar.core.security.isExecutedWithinNode")).booleanValue();
      if (exec == true) {
	log.warn("Unable to get crypto Client policy");
      }
      else {
	if (log.isInfoEnabled()) {
	  log.info("Unable to get crypto Client policy");
	}
      }
      throw new RuntimeException("Unable to get crypto Client policy");
    }
    // Keystore to store key pairs
    param = new DirectoryKeyStoreParameters();
    String nodeDomain = cachecryptoClientPolicy.getCertificateAttributesPolicy().domain;
    nodeConfiguration = new NodeConfiguration(nodeDomain, serviceBroker);
    param.keystorePath = nodeConfiguration.getNodeDirectory()
      + cachecryptoClientPolicy.getKeystoreName();
    log.debug("going to use smart card: " + cachecryptoClientPolicy.getUseSmartCard());
    if (cachecryptoClientPolicy.getUseSmartCard()) {
      try {
	param.keystorePassword =
	  SmartCardApplet.getKeystorePassword(cachecryptoClientPolicy.getKeystorePassword(),
					      log);

      } catch (RuntimeException e) {
	log.error("Couldn't talk to the keystore");
	throw e;
      }
    } else {
      param.keystorePassword = cachecryptoClientPolicy.getKeystorePassword().toCharArray();
    } // end of else

    File file = new File(param.keystorePath);
    if (!file.exists()){
      if (log.isInfoEnabled()) {
	log.info(param.keystorePath +
		 " keystore does not exist. Creating...");
      }
      try {
	KeyStore k = KeyStore.getInstance(KeyStore.getDefaultType());
	FileOutputStream fos = new FileOutputStream(param.keystorePath);
	k.load(null, param.keystorePassword);
	k.store(fos, param.keystorePassword);
	fos.close();
      }
      catch (Exception e) {
	log.warn("Unable to get keystore:" + e);
	throw new RuntimeException("Unable to get keystore:" + e);
      }
    }
    try {
      param.keystoreStream = new FileInputStream(param.keystorePath);
      //param.isCertAuth = configParser.isCertificateAuthority();
    }
    catch (Exception e) {
      log.warn("Unable to open keystore:" + e);
      throw new RuntimeException("Unable to open keystore:" + e);
    }

    // CA keystore parameters
    ConfigFinder configFinder = ConfigFinder.getInstance();
    param.caKeystorePath = nodeConfiguration.getNodeDirectory()
      + cachecryptoClientPolicy.getTrustedCaKeystoreName();
    param.caKeystorePassword =
      cachecryptoClientPolicy.getTrustedCaKeystorePassword().toCharArray();

    if (log.isDebugEnabled()) {
      log.debug("CA keystorePath=" + param.caKeystorePath);
    }
    File cafile = new File(param.caKeystorePath);
    if (!cafile.exists()) {
      if (log.isInfoEnabled()) {
	log.info(param.caKeystorePath +
		 "Trusted CA keystore does not exist. in "
		 + param.caKeystorePath + ". Trying with configFinder");
      }
      File cafile2 = configFinder.locateFile(cachecryptoClientPolicy.getTrustedCaKeystoreName());
      if (cafile2 != null) {
	param.caKeystorePath = cafile2.getPath();
      }
      else {
        /**
         * Create trusted keystore anyway, if no trusted cert is installed
         * later then this node simply cannot do anything
         * */
        if (log.isInfoEnabled()) {
          log.info(param.caKeystorePath +
                   " Trusted CA keystore does not exist. Creating...");
        }
        try {
          KeyStore k = KeyStore.getInstance(KeyStore.getDefaultType());
          FileOutputStream fos = new FileOutputStream(param.caKeystorePath);
          k.load(null, param.caKeystorePassword);
          k.store(fos, param.caKeystorePassword);
          fos.close();
        }
        catch (Exception e) {
          log.warn("Unable to create CA keystore:" + e);
          throw new RuntimeException("Unable to create CA keystore:" + e);
        }
      }
    }

    try {
      param.caKeystoreStream = new FileInputStream(param.caKeystorePath);
    }
    catch (Exception e) {
      if (log.isWarnEnabled()) {
	log.warn("Warning: Could not open CA keystore ("
		 + param.caKeystorePath + "):" + e);
      }
      param.caKeystoreStream = null;
      param.caKeystorePath = null;
      param.caKeystorePassword = null;
    }

    if (log.isDebugEnabled()) {
      log.debug("Secure message keystore: path="
		+ param.keystorePath);
      log.debug("Secure message CA keystore: path="
		+ param.caKeystorePath);
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
	  log.error(" Erroe in getting ca keystore "+e.getMessage(), new Throwable());
	  // Unable to use CA keystore. Do not use it
	  caKeystore = null;
	  param.caKeystorePassword = null;
	}
      }
      // Initialize commonName2alias hash map
      initCN2aliasMap();

      if (log.isDebugEnabled()) {
	log.debug("listing keys store");
	listKeyStoreAlias(keystore, param.keystorePath);
	log.debug("listing CA keys store");
	listKeyStoreAlias(caKeystore, param.caKeystorePath);
      }
      initCertCache();
    }
    catch (Exception e) {
      log.error("Unable to initialize Certificate Cache : ", e);
    }
    if (param.keystoreStream != null) {
      try {
	param.keystoreStream.close();
      }
      catch (Exception e) {
	log.warn("Unable to close keystore:" + e);
	throw new RuntimeException("Unable to close keystore:" + e);
      }
    }
    if (param.caKeystoreStream != null) {
      try {
	param.caKeystoreStream.close();
      }
      catch (Exception e) {
	log.warn("Unable to close CA keystore:" + e);
	throw new RuntimeException("Unable to close CA keystore:" + e);
      }
    }
    
    
  }

  private void initCN2aliasMap()
    {
      Key[] keys = getCertificates();
      for (int i = 0 ; i < keys.length ; i++) {
	if (keys[i].cert instanceof X509Certificate) {
	  X509Certificate aCert = (X509Certificate) keys[i].cert;
	  X500Name dname = CertificateUtility.getX500Name(aCert.getSubjectDN().getName());
	  commonName2alias.put(getCommonName(dname), keys[i].alias);
	}
      }
      if (log.isDebugEnabled()) {
	Set st = commonName2alias.keySet();
	Iterator it = st.iterator();
	log.debug("CommonName to Alias Hash map contains:");
	while (it.hasNext()) {
	  String cn = (String) it.next();
	  log.debug("cn=" + cn + " <-> " + commonName2alias.get(cn));
	}
      }
    }

  
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
	if (log.isErrorEnabled()) {
	  log.error("Unable to get list of aliases in keystore");
	}
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
	  if (log.isErrorEnabled()) {
	    log.error("Unable to get certificate for " + alias);
	  }
	}
      }
      Key[] keyReply = new Key[certificateList.size()];
      for (int i = 0 ; i < certificateList.size() ; i++) {
	keyReply[i] = (Key) certificateList.get(i);
      }

      return keyReply;
    }

  
  /** Dump all the key aliases in a keystore */
  private void listKeyStoreAlias(KeyStore ks, String path) {
    if (ks == null) {
      log.debug("listKeyStoreAlias. Null keystore");
      return;
    }
    try {
      Enumeration alias = ks.aliases();
      log.debug("Keystore " + path + " contains:");
      while (alias.hasMoreElements()) {
	//build up the hashMap
	String a = (String)alias.nextElement();
	X509Certificate x=(X509Certificate)ks.getCertificate(a);
	log.debug("  " + a);
      }
    }
    catch(Exception e) {
      log.warn("Unable to list keystore alias:" + e.toString());
    }
  }

  private List getCertificates(String distinguishedName)
    {
      List list = null;
      try {
	list = (List) certsCache.get(distinguishedName);
      }
      catch (Exception e) {
	log.warn("Unable to get list of certificates from cache for "
		 + distinguishedName + ". Reason:" + e);
      }
      return list;
    }

  /** Return all the certificates associated with a given distinguished name */
  public List getCertificates(X500Name x500Name)
    {
      if (x500Name == null) {
	throw new IllegalArgumentException("getCertificate: Argument is null");
      }
      return getCertificates(x500Name.getName());
    }

  /** Change certificate status in the certificate cache */
  public void revokeCertificate(Certificate certificate)
    {
    }

  public void addToRevokedCache(String issuerDN, BigInteger serialno) {
    // need to keep this information, so that once we receive a certificate we know
    // immediately whether it has been revoked.
    String cacheString = issuerDN + "," + serialno;
    // printbigIntCache();
    if (log.isDebugEnabled()) {
      
      log.debug("addToRevokedCache - " + cacheString);
    }
    revokedCache.put(cacheString, cacheString);
  }

  /**
   */
  public  void revokeStatus(BigInteger serialno, String issuerDN, String subjectDN) {
    if(subjectDN==null) {
      return;
    }
    List list=getCertificates(subjectDN);
    if(list.size()==0){
      log.warn("cert not found in cache:");
      return ;
    }
    ListIterator it = list.listIterator();
    boolean found = false;
    while (it.hasNext()) {
      CertificateStatus aCertEntry = null;
      aCertEntry = (CertificateStatus) it.next();
      X509Certificate c1 = aCertEntry.getCertificate();
      String issuername=c1.getIssuerDN().getName();
      BigInteger certserialno=c1.getSerialNumber();
      if((issuername.equals(issuerDN))&&(certserialno.equals(serialno))){
	found=true;
	// Give the opportunity to invalidate existing or future sessions that
	// currently use this certificate.
	invalidateSessions(c1);

	aCertEntry.setCertificateTrust( CertificateTrust.CERT_TRUST_REVOKED_CERT);

	log.debug("revoked status in cache:");
	X500Name subjectname=null;
        String cname = null;
	try {
	  subjectname= new X500Name(subjectDN);
          cname = subjectname.getCommonName();
	}
	catch(IOException ioexp) {
	  if (log.isWarnEnabled()) {
	    log.warn("Unable to get X500 name: " + subjectDN, ioexp);
	  }
	}
	certsCache.put(subjectname.getName(),list);
	log.debug("revoked status in cache:" + subjectDN);
        // inform validity listeners
        CertValidityService validityService = (CertValidityService)
          serviceBroker.getService(this, CertValidityService.class, null);
        validityService.invalidate(cname);
        serviceBroker.releaseService(this, CertValidityService.class, validityService);
	break;
      }

    }
    if(!found){
      log.warn(" not found cert:");
      return;
    }

    // should check all certificate status, checkCertificate in cert cache
    // does not check cert chain, so the cert issued by a revoked signer
    // would still be considered valid
    KeyRingService ks =  (KeyRingService)serviceBroker.getService(this,
                                                                  KeyRingService.class,
                                                                  null);
    if(ks==null) {
      log.warn(" Cannot revoke status as KeyRingService is null :") ;
      return ;
    }
    Enumeration allcerts = certsCache.elements();
    while (allcerts.hasMoreElements()) {
      List certList = (List)allcerts.nextElement();
      it = certList.listIterator();
      while (it.hasNext()) {
        CertificateStatus cs = (CertificateStatus)it.next();
        if (cs.isValid()) {
          ks.checkCertificate(cs, true, true);
        }
      }
    }
    serviceBroker.releaseService(this,
                                 KeyRingService.class,
                                 ks);
  }

  /** Provide the opportunity to invalidate existing or future sessions that use a given certificate.
   */
  private void invalidateSessions(X509Certificate cert) {
    KeyRingSSLFactory.invalidateSession(cert);
    KeyRingSSLServerFactory.invalidateSession(cert);
  }


  public boolean checkRevokedCache(X509Certificate certificate) {
    boolean revoked = false; 

    // is it revoked?
    String subjectDN = certificate.getSubjectDN().getName();
    String issuerDN = certificate.getIssuerDN().getName();
    BigInteger serialno = certificate.getSerialNumber();
    if (revokedCache.get(issuerDN + "," + serialno) != null) {
      if (log.isDebugEnabled()) {
	log.debug("Certificate found in revokedCache: " + subjectDN);
      }
      revoked = true;
    }

    // find cert status
    List list = getCertificates(subjectDN);
    CertificateStatus cs = null;
    if (list != null) {
      ListIterator it = list.listIterator();
      while (it.hasNext()) {
        cs = (CertificateStatus)it.next();
        if (cs.getCertificate().getPublicKey().equals(certificate.getPublicKey())) {
          if (!cs.getCertificateTrust().equals(CertificateTrust.CERT_TRUST_REVOKED_CERT)) {
            if (revoked) {
              cs.setCertificateTrust(CertificateTrust.CERT_TRUST_REVOKED_CERT);
            }
          }
          else {
            revoked = true;
          }
          break;
        }
        cs = null;
      }
    }
    if (cs == null) {
      if (log.isDebugEnabled()) {
        log.debug("Certificate being checked is not in cert cache: " + certificate.getSubjectDN());
      }
    }
    return revoked;
  }

  private CertificateStatus addCertStatus(List list, 
                                          CertificateStatus certEntry,
					  PrivateKey privkey) throws SecurityException {
    CertificateStatus ret = certEntry;
    
    if(certEntry != null) {
      X509Certificate cert = certEntry.getCertificate();
      // Retrieve the distinguished name, which is used as a key in
      // the certificate cache.
      Principal principal = cert.getSubjectDN();

      // Are there existing certificates for this principal?
      // If yes, add the new certificate to the List. Otherwise, create a
      // new entry in the hash table.
      PrivateKeyCert pcert = null;

      if (privkey != null) {
        pcert = new PrivateKeyCert(privkey, certEntry);
        if (log.isDebugEnabled()) {
          log.debug("add Private Key:" + principal);
        }
      }
      else {
        if (log.isDebugEnabled()) {
          log.debug("add Certificate:" + principal);
        }
      }
      if (log.isDebugEnabled()) {
        String a = certEntry.getCertificateAlias();

        log.debug((a != null ? "Alias: " + a + "." : "" )
                  + "Trust:" + certEntry.getCertificateTrust()
                  + ". Type: " + certEntry.getCertificateType()
                  + ". Origin: " + certEntry.getCertificateOrigin()
                  + ". Valid: " + certEntry.isValid());
      }
      if(list.size() == 0) {
        if (privkey != null) {
          list.add(pcert);
        }
        else {
          list.add(certEntry);
        }
        if (log.isDebugEnabled()) {
          log.debug(" (first certificate)");
        }
      } else {
        Date notBefore = cert.getNotBefore();
        /* If the certificate is already in the list, update the certificate
         * status fields, otherwise create a new entry in the list. */
        ListIterator it = list.listIterator();
        boolean found = false;
        while (it.hasNext()) {
          CertificateStatus aCertEntry = null;
          if (privkey != null) {
            aCertEntry = ((PrivateKeyCert) it.next()).getCertificateStatus();
          }
          else {
            aCertEntry = (CertificateStatus) it.next();
          }
          Certificate c1 = aCertEntry.getCertificate();
          // Compare the public keys, not the certificates. The certificate
          // may change, for instance when it has been signed by a CA.
          if (c1.getPublicKey().equals(cert.getPublicKey())) {
            // The certificate exists in the list.
            // Update the certificate trust field with the new one.
            // All other fields cannot change.
            if((aCertEntry.isValid()==false)&&(certEntry.isValid()==false)) {
              return ret;
            }

            /*
              A certificate which is both in the node keystore and the trusted CA
              keystore is a CA certificate.
              if (aCertEntry.getCertificateType() != certEntry.getCertificateType()) {
              //|| aCertEntry.getCertificateOrigin() != certEntry.getCertificateOrigin()) {
              // Error. Certificate type and Certificate Origin cannot change
              if (log.isDebugEnabled()) {
              log.debug("Error. Trying to update immutable fields: ");
              log.debug("   " + aCertEntry.getCertificateType() + " ==> "
              + certEntry.getCertificateType());
              log.debug("   " + aCertEntry.getCertificateOrigin() + " ==> "
              + certEntry.getCertificateOrigin());
              }
              throw new SecurityException("Error. Trying to update immutable fields");
              }
            */
            if (log.isDebugEnabled()) {
              log.debug("\nUpdating certificate status. Old trust:"
                        + aCertEntry.getCertificateTrust()
                        + " - new trust:"
                        + certEntry.getCertificateTrust());
            }
            // Update type
            aCertEntry.setCertificateType(certEntry.getCertificateType());
            // Update trust.
            aCertEntry.setCertificateTrust(certEntry.getCertificateTrust());
            // Update certificate (the signature may have changed)
            aCertEntry.setCertificate(certEntry.getCertificate());
            /**
             // Update the orgin IFF the old origin is ORI_LDAP AND new origin is ORI_KEYSTORE.
             // Otherwise, don't change it.
             //
             // This condition could occur when an agent moves from agent X to node Y.
             // However, before agent X  moves, communication between node  Y (or an agent in
             // node Y) and agent X occurs.  This event will cause an ldap lookup for the 
             // certificate for agent X, resulting in a new entry in the  certificate cache with
             // origin as CERT_ORI_LDAP. But when agent X moves to node Y, during the unwrapping
             // process, we add the certificate from the move to the certificate cache .  However, 
             // when we added the certificate to the cache (in this code), we don't update the 
             // status of the original entry with origin of CERT_ORI_LDAP to CERT_ORI_KEYSTORE.
             // Therefore, if we move agent X again, we can't find its certificate since we search
             // based on KeyRingService.LOOKUP_KEYSTORE which effectively looks for certificates
             // with the origin CERT_ORI_LDAP.
             */
            if(aCertEntry.getCertificateOrigin().equals(CertificateOrigin.CERT_ORI_LDAP) &&
               certEntry.getCertificateOrigin().equals(CertificateOrigin.CERT_ORI_KEYSTORE)) {  
              if(log.isDebugEnabled()) {
                log.debug("Changing the origin of the certificate cache entry from " + aCertEntry.getCertificateOrigin() + 
                          " to " + certEntry.getCertificateOrigin() + " for " + 
                          certEntry.getCertificate().getSubjectDN().getName());
              }
              aCertEntry.setCertificateOrigin(certEntry.getCertificateOrigin());
            }
            ret = aCertEntry;
            found = true;
            break;
          }
        }

        if(!found) {
          // Reset the iterator.
          it = list.listIterator();
          while (it.hasNext()) {
            CertificateStatus ce = null;
            if (privkey != null) {
              ce = ((PrivateKeyCert) it.next()).getCertificateStatus();
            }
            else {
              ce = (CertificateStatus) it.next();
            }

            Date nb = ((X509Certificate)ce.getCertificate()).getNotBefore();
            if (notBefore.after(nb) || !ce.isValid()) {
              // Insert certificate right before the current certificate
              it.previous();
              if (privkey != null) {
                it.add(pcert);
              }
              else {
                it.add(certEntry);
              }
              if (log.isDebugEnabled()) {
                log.debug(" (insert before index=" + it.nextIndex()
                          + " - size="
                          + list.size() + ")");
              }
              // Certificate was successfully inserted in the list.
              break;
            }
          }
          if (!it.hasNext()) {
            // Certificate was not added. Add it at the end of the list
            if (privkey != null) {
              list.add(pcert);
            }
            else {
              list.add(certEntry);
            }
            if (log.isDebugEnabled()) {
              log.debug(" (insert at list end. List size=" + list.size() + ")");
            }
          }
        }
      }
    }
    return ret;
  }

  /** Add a certificate to the cache */
  public CertificateStatus addCertificate(CertificateStatus certEntry)  {

    CertificateStatus ret = certEntry;
    if(certEntry != null) {
      X509Certificate cert = certEntry.getCertificate();
      // Retrieve the distinguished name, which is used as a key in
      // the certificate cache.
      Principal principal = cert.getSubjectDN();

      if(log.isDebugEnabled()) {
        log.debug("$ Certificate dn name is :"
                  +principal.getName());
        log.debug("$ Certificate Issuer dn name is :"
                  +cert.getIssuerDN().getName());
        log.debug("$ Trust of cert is :"
                  +certEntry.getCertificateTrust());
      }
      if((certEntry.getCertificateTrust()==
          CertificateTrust.CERT_TRUST_CA_SIGNED) ||
         (certEntry.getCertificateTrust()
          == CertificateTrust.CERT_TRUST_CA_CERT))    {
        updateBigInt2Dn(cert, true);
      }
      else {
        if(log.isInfoEnabled())
          log.info("Certificate " + principal.getName() + " is not trusted yet trust="
                   + certEntry.getCertificateTrust());
      }

      List list = (List)certsCache.get(principal.getName());
      if (list == null) {
        list = Collections.synchronizedList(new ArrayList());
      }

      if(log.isDebugEnabled()) {
        log.debug("CertificateCache.addCertificate");
      }
      ret = addCertStatus(list, certEntry, null);
      certsCache.put(principal.getName(), list);
      if(certEntry.getCertificateType()==CertificateType.CERT_TYPE_CA) {
        if(_blackboardService!=null) {
          if(log.isDebugEnabled()) {
            log.debug("Calling publishDNtoBB for DN :" +principal.getName() );
          }
          publishDNtoBB(principal.getName());
        }
        if(_crlCacheService!=null) {
          _crlCacheService.addToCRLCache(cert.getSubjectDN().getName());
          log.debug("Update CRL Cache with DN :"+ cert.getSubjectDN().getName());
        }
        else {
          log.debug("CRL Cache Service is NULL in addCertificate(CertificateStatus certEntry) .. cannot update CRL cache with DN:"+
                    cert.getSubjectDN().getName()); 
          if(serviceAvailableListener==null) {
            log.debug("Adding CRL cache Service Listner :");
            serviceAvailableListener=new MyServiceAvailableListener();
            serviceBroker.addServiceListener(serviceAvailableListener);
          } 
        
        }// end of else
        if (_eventService != null && _eventService.isEventEnabled()) {
          sendEvent(cert.getSubjectDN().getName());
        }
      }// end of if(certEntry.getCertificateType()==CertificateType.CERT_TYPE_CA)
    }// end of if(certEntry != null)
    return ret;
  }

  /**
   * @param actionIsPut: true if adding to hashtable. false if removing from hashtable.
   */
  public void updateBigInt2Dn(X509Certificate cert, boolean actionIsPut) {

    CRLKey crlkey=null;
    String subjectDN=cert.getSubjectDN().getName();
    String issuerDN=cert.getIssuerDN().getName();
    BigInteger bigint=cert.getSerialNumber();
    crlkey=new CRLKey(bigint,issuerDN);

    if (actionIsPut) {
      if(bigint2dn.contains(crlkey) && log.isWarnEnabled()) {
	log.warn("Bigint to dn mapping already contains key. "
		 + crlkey.toString() + ". Overriding existing entry :"
		 + bigint2dn.get(crlkey));
      }
      else {
	if(log.isDebugEnabled()) {
	  log.debug(" Adding entry to Bigint to dn mapping "
		    +crlkey.toString() + "subjectdn ::" +subjectDN);
	}
      }
      bigint2dn.put(crlkey,subjectDN);
    }
    else {
      if(log.isDebugEnabled()) {
	log.debug(" Removing entry to Bigint to dn mapping "
		  +crlkey.toString() + "subjectdn ::" +subjectDN);
      }
      bigint2dn.remove(crlkey);
    }
    if(log.isDebugEnabled()) {
      printbigIntCache();
    }
  }

  private List getPrivateKeys(String distinguishedName)  {

    List list = (List) privateKeyCache.get(distinguishedName);
    if(list==null) {
      log.debug(" Error in getting certificate for dn :"+distinguishedName);
      Set x=privateKeyCache.keySet();
      if(x!=null) {
        Iterator iter=x.iterator();
        while(iter.hasNext()){
          log.debug(" Key in private Key cache is :"+(String)iter.next());
        }
      }
      else {
        log.debug("Set in getPrivateKeysis null:");
      }
	
    }
    return list;
  }

  /** Return all the private keys associated with a given distinguished name */
  public List getPrivateKeys(X500Name x500Name)  {

    return getPrivateKeys(x500Name.getName());
  }


  /** Add a private key to the cache */
  public void addPrivateKey(PrivateKey privatekey, CertificateStatus certEntry)  {
    
    X509Certificate cert = (X509Certificate) certEntry.getCertificate();
    // Retrieve the distinguished name, which is used as a key in
    // the certificate cache.
    Principal principal = cert.getSubjectDN();

    // Are there existing private keys for this principal?
    // If yes, add the new private key to the List. Otherwise, create a
    // new entry in the hash table.
    List list = (List)privateKeyCache.get(principal.getName());
    if (list == null) {
      list = Collections.synchronizedList(new ArrayList());
    }

    if(log.isDebugEnabled()) {
      log.debug("CertificateCache.addPrivateKey");
    }
    addCertStatus(list, certEntry, privatekey);

    privateKeyCache.put(principal.getName(), list);
  }

  public void printbigIntCache() {
    Enumeration e=bigint2dn.keys();
    CRLKey keys=null ;
    String dnname=null;
    log.debug("Printing contents of bigint 2dn mapping in certcache");
    int counter =0;
    while(e.hasMoreElements()) {
      keys=(CRLKey)e.nextElement();
      log.debug(" counter :"+ counter);
      log.debug("In bigint cache  Key is :"
                +keys.toString() +" hash code is :"+keys.hashCode());
      dnname=(String)bigint2dn.get(keys);
      log.debug("In bigint cache dn name is :: "+dnname);
      counter++;
    }
  }
  public void printCertificateCache() {

    // Certificates
    Enumeration e = certsCache.keys();
    log.debug("============== Certificates:");
    while (e.hasMoreElements()) {
      String name = (String) e.nextElement();
      List list = (List) certsCache.get(name);
      ListIterator it = list.listIterator();
      log.debug("Certificates for: " + name);
      while (it.hasNext()) {
        CertificateStatus cs = (CertificateStatus) it.next();
        log.debug(cs.toString());
      }
    }

    // Private keys
    e = privateKeyCache.keys();
    log.debug("============== Private keys:");
    while (e.hasMoreElements()) {
      String name = (String) e.nextElement();
      List list = (List) privateKeyCache.get(name);
      ListIterator it = list.listIterator();
      log.debug("PrivateKeys for: " + name);
      while (it.hasNext()) {
        PrivateKeyCert pcert = (PrivateKeyCert) it.next();
        log.debug(pcert.toString());
      }
    }
  }

  public String getDN(CRLKey crlkey)  {

    if(log.isDebugEnabled())
      log.debug("Going to find dn for key :"+crlkey.toString());
    String subjectDN=null;
    if(bigint2dn.containsKey(crlkey)) {
      subjectDN=(String)bigint2dn.get(crlkey);
    }
    return subjectDN;

  }

  public Enumeration getKeysInCache() {
    
    return certsCache.keys();
  }

  
  public void deleteEntry(X500Name name) {
    if (name == null) {
      log.warn("Unable to remove null entry from cache.");
      throw new IllegalArgumentException("Unable to remove null entry from cache.");
    }
    String distinguishedName = name.getName();

    // Update the CRL hashtable
    List certList = getCertificates(distinguishedName);
    Iterator it = certList.iterator();
    CertificateStatus certstatus = null;
    while (it.hasNext()) {
      if (log.isDebugEnabled()) {
	log.debug("Removing " + distinguishedName + " from CRL checking hashtable");
      }
      certstatus = (CertificateStatus) it.next();
      updateBigInt2Dn(certstatus.getCertificate(), false);
    }

    if (log.isDebugEnabled()) {
      log.debug("Removing " + distinguishedName + " from certificate cache");
    }

    certsCache.remove(distinguishedName);
    privateKeyCache.remove(distinguishedName);
  }

  private void initCertCache() {
    /*
      to be deleted 
      certCache = new CertificateCache(this, log);
    */
    /** a hashtable to store selfsigned CA certificate common names **/
    //  Hashtable selfsignedCAs = new Hashtable();
    try {
      if(keystore.size() > 0) {
	// Build a hash table that indexes keys in the keystore by DN
	if (log.isDebugEnabled()) {
	  log.debug("++++++ Initializing Certificate Cache");
	}
	initCertCacheFromKeystore(keystore, param.keystorePassword,
				  CertificateType.CERT_TYPE_END_ENTITY);
      }
    }
    catch (KeyStoreException e) {
      if (log.isErrorEnabled()) {
	log.error("Unable to access keystore: " + e);
      }
    }

    try {
      if(caKeystore != null && caKeystore.size() > 0) {
	if (log.isDebugEnabled()) {
	  log.debug("++++++ Initializing CA Certificate Cache");
	}
	// Build a hash table that indexes keys in the CA keystore by DN
	initCertCacheFromKeystore(caKeystore, param.caKeystorePassword,
				  CertificateType.CERT_TYPE_CA);
      }
    }
    catch (KeyStoreException e) {
      if (log.isErrorEnabled()) {
	log.error("Unable to access CA keystore: " + e);
      }
    }
    
    if (log.isDebugEnabled()) {
      printCertificateCache();
      log.debug("Certificate Cache is initilized: ");
    }
  }

  /** Build a hashtable containing certificates. Since an entity (user, agent...)
   * may have multiple keys, each entry in the hashtable contains a Vector
   * of all the certificates for that entity. */
  private void initCertCacheFromKeystore(KeyStore aKeystore, 
                                         char[] password,
					 CertificateType certType) throws KeyStoreException  {
    
    for(Enumeration enumeration = aKeystore.aliases(); enumeration.hasMoreElements(); ) {
      String alias = (String) enumeration.nextElement();
      X509Certificate certificate =
        (X509Certificate) aKeystore.getCertificate(alias);

      if(certificate != null) {
        // Update private key cache
        PrivateKey key = null;
        try {
          key = (PrivateKey) aKeystore.getKey(alias, password);
        }
        catch (Exception e) {
          log.warn("Unable to update private keystore: " + e);
        }
        addKeyToCache(certificate, key, alias, certType);
      }
      else {
        log.error("Keystore is bad");
        throw new RuntimeException("Keystore is bad");
      }
    }
  }
  
 

 
  public String getCommonName(String alias)  {
    String cn=null;
    try {
      X509Certificate cert=(X509Certificate)keystore.getCertificate(alias);
      cn=getCommonName(cert);
    }
    catch (Exception exp) {
      log.warn("Unable to get common name for " + alias + ". Reason:" + exp);
    }
    return cn;

  }

  public  String getCommonName(X509Certificate x509)  {
    X500Name clientX500Name = CertificateUtility.getX500Name(x509.getSubjectDN().toString());
    return getCommonName(clientX500Name);
  }

  public String getCommonName(X500Name dname)  {
    try {
      return dname.getCommonName();
    } catch (IOException iox) {
      if (log.isErrorEnabled()) {
        log.error("Unabled to get common name for - " + dname);
      }
    }
    return null;
  }

  public boolean setCertificateTrust(X509Certificate certificate, 
                                     CertificateStatus cs,
                                     X500Name name, 
                                     Hashtable selfsignedCAs) {
    
    boolean isTrusted = false; // Raise a warning if there is no trusted cert for that entity.
    KeyRingService ks =  (KeyRingService)serviceBroker.getService(this,
                                                                  KeyRingService.class,
                                                                  null);
    if(ks==null) {
      return isTrusted;
    }
    try {
      X509Certificate[] certs = ks.checkCertificateTrust(certificate);
      // Could establish a certificate chain. Certificate is trusted.
      // Update Certificate Status.
      if (log.isDebugEnabled()) {
        log.debug("Certificate chain established for " + certificate.getSubjectDN().getName());
      }
      cs.setCertificateTrust(CertificateTrust.CERT_TRUST_CA_SIGNED);
      updateBigInt2Dn(certificate, true);
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
        if (!cachecryptoClientPolicy.isRootCA() &&
            cachecryptoClientPolicy.isCertificateAuthority()) {
	  // We are a subordinate CA
	  if (cs.getCertificateType() == CertificateType.CERT_TYPE_CA) {
	    // should this be moved to after initialization?
            String cn = getCommonName(name);
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
    serviceBroker.releaseService(this,
                                 KeyRingService.class,
                                 ks);
    return isTrusted;
  }

  public CertificateStatus addKeyToCache(X509Certificate certificate, 
                                         PrivateKey key,
                                         String alias, 
                                         CertificateType certType) {
    

    if (certificate == null) {
      log.warn("Unable to add null certificate to cache");
      throw new IllegalArgumentException("Unable to add null certificate to cache");
    }
    CertificateStatus certstatus = null;
    CertificateTrust trust = CertificateTrust.CERT_TRUST_UNKNOWN;
    try {
      if (certType == CertificateType.CERT_TYPE_CA) {
	if(cachecryptoClientPolicy==null) {
	  log.error(" Got cryptoClientPolicy as NULL ");
	}
	// cannot trust it automatically, need to be in the trust store
	if (cachecryptoClientPolicy.isRootCA() || caKeystore.getCertificate(alias) != null)
	  trust = CertificateTrust.CERT_TRUST_CA_CERT;
        // this is a hack, for unzip & run to install CA certificates
        // and make them trusted
        if (key == null) {
          trust = CertificateTrust.CERT_TRUST_CA_CERT;
        }
      }
    }
    catch (java.security.KeyStoreException e) {
      log.warn("Unable to get certificate from keystore: " + e);
    }
    certstatus =
      new CertificateStatus(certificate,
			    CertificateOrigin.CERT_ORI_KEYSTORE,
			    CertificateRevocationStatus.VALID,
			    certType,
			    trust, alias);
    // Update certificate cache
    if (log.isDebugEnabled()) {
      log.debug("addCertificate from keystore");
    }
    // Add the certificate to the cache.
    // The certificate status may be an update, so we need to retrieve
    // the real certificate status from the cache.
    certstatus = addCertificate(certstatus);
    // Update Common Name to DN hashtable
    nameMapping.addName(certstatus);
    /*
      there is no need to update CRL Cache as it is already being done in 
      addCertificate method 
      -- Rakesh 
      
      if(certType == CertificateType.CERT_TYPE_CA) {
      if(_crlCacheService!=null) {
      log.debug("Adding to  CRL cache dn:"+certificate.getSubjectDN().getName());
      _crlCacheService.addToCRLCache(certificate.getSubjectDN().getName());
      }
      else {
      log.debug ("CRL cache Service is NULL in addKeyToCache method  . Unable to update CRL cache for dn:"
      +certificate.getSubjectDN().getName());
      if(serviceAvailableListener==null) {
      log.debug("Adding CRL cache Service Listner :");
      serviceAvailableListener=new MyServiceAvailableListener();
      serviceBroker.addServiceListener(serviceAvailableListener);
      }
      }
      }
    */
    if (key != null) {
      if (log.isDebugEnabled()) {
	log.debug("add Private Key from keystore");
      }
      // Add the private key to the cache
      addPrivateKey(key, certstatus);
    }
    return certstatus;
  }

  public static String getTitle(String commonName) {
    String title = CERT_TITLE_AGENT;
    if (commonName.equals(NodeInfo.getNodeName()))
      title = CERT_TITLE_NODE;
    else if (commonName.equals(NodeInfo.getHostName()))
      title = CERT_TITLE_SERVER;
    return title;
  }


  public Enumeration getAliasList()  {
    
    Enumeration alias;
    try {
      alias =keystore.aliases();
    }
    catch (Exception exp) {
      log.warn("Unable to get alias list: " + exp);
      return null;
    }
    return alias;

  }

  public KeyStore getKeyStore() {
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("getKeyStore"));
    }
    return keystore;
  }

  public List getX500NameFromNameMapping(String commonName){
    if(nameMapping!=null) {
      return nameMapping.getX500Name(commonName);
    }
    return null;
        
  }

  public boolean  presentInNameMapping(X500Name dname){
    if(nameMapping!=null) {
      return nameMapping.contains(dname);
    }
    return false;
  }
  
  public void addNameToNameMapping(CertificateStatus certStatus){
    if(nameMapping!=null) {
      nameMapping.addName(certStatus);
    }
  }
  
  /**
   * When used in user application, the privatekey is password protected,
   * this function is used as generic fuction to add certificate to cache.
   */
  public void addCertificateToCache(String alias,
                                    X509Certificate importCert,
                                    PrivateKey privatekey) {
      
    CertificateStatus certstatus =
      new CertificateStatus(importCert,
                            CertificateOrigin.CERT_ORI_KEYSTORE,
			    CertificateRevocationStatus.VALID,
                            CertificateType.CERT_TYPE_END_ENTITY,
                            CertificateTrust.CERT_TRUST_CA_SIGNED, alias);
    // need to check whether it is a CA
    String title = CertificateUtility.findAttribute(importCert.getSubjectDN().getName(), "t");
    if (title != null && title.equals(CERT_TITLE_CA)) {
      certstatus.setCertificateType(CertificateType.CERT_TYPE_CA);
    }

    if (log.isDebugEnabled()) {
      log.debug("Update cert status in hash map. AddPrivateKey");
    }
    addCertificate(certstatus);
    addPrivateKey(privatekey, certstatus);
    // Update Common Name to DN hashtable
    nameMapping.addName(certstatus);
  }

  public void addSSLCertificateToCache(X509Certificate sslCert) {
    String dname = sslCert.getSubjectDN().getName();
    X500Name x500name = CertificateUtility.getX500Name(dname);
    List certList = getCertificates(x500name);

    // if found don't add it again
    if (certList != null && certList.size() != 0) {
      return;
    }

    String title = CertificateUtility.findAttribute(dname, "t");
    CertificateType certType = CertificateType.CERT_TYPE_END_ENTITY;
    if (title != null && title.equals(CERT_TITLE_CA))
      certType = CertificateType.CERT_TYPE_CA;
    CertificateStatus certstatus =
      new CertificateStatus(sslCert,
                            CertificateOrigin.CERT_ORI_SSL,
			    CertificateRevocationStatus.VALID,
                            certType,
                            CertificateTrust.CERT_TRUST_CA_SIGNED, null);
    if (log.isDebugEnabled()) {
      log.debug("Update sslCert status in hash map: " + dname);
    }
    /*
      there is no need to add the certificate to CRL Cache here as it will be done in 
      addCertificate
      -- Rakesh
      if(certType == CertificateType.CERT_TYPE_CA ) {
      if(_crlCacheService!=null) {
      _crlCacheService.addToCRLCache(dname);
      }
      else {
      log.warn("Unable to add ssl certificate to CRL Cache as CRL Cache service is null:"+dname); 
      }
     
      }
    */
    addCertificate(certstatus);
    nameMapping.addName(certstatus);
  }

  public void removeEntryFromCache(String commonName) {
    if (log.isInfoEnabled()) {
      log.info("Removing entry from certificate cache:" + commonName);
    }
    List nameList = nameMapping.getX500Name(commonName);
    if (nameList == null) {
      if (log.isDebugEnabled()) {
        log.debug("removeEntryFromCache: no entry in nameMapping found for " + commonName);
      }
      return;
    }
    for (int i = 0; i < nameList.size(); i++) {
      X500Name x500Name = (X500Name)nameList.get(i);
      deleteEntry(x500Name);
      if (log.isDebugEnabled()) {
        printCertificateCache();
      }
    }
  }

  public String findAlias(X500Name adname) {
    Key[] keys = getCertificates();
    String alias = null;

    if(keys!=null) {
      for (int i = 0 ; i < keys.length ; i++) {
	if (keys[i].cert instanceof X509Certificate) {
	  X509Certificate aCert = (X509Certificate) keys[i].cert;
	  if (adname.getName().equals(aCert.getSubjectDN().getName())) {
	    return keys[i].alias;
	  }
	}
      }
    }
    return alias;
  }
  
  private void addCN2alias(String alias, X509Certificate x509)
    {
      String cn = getCommonName(x509);
      if (log.isDebugEnabled()) {
        log.debug("addCN2alias: " + cn + "<->" + alias);
      }
      commonName2alias.put(cn, alias);
    }

  private void removeCN2alias(String cn)
    {
      String alias = (String) commonName2alias.get(cn);
      if (log.isDebugEnabled()) {
        log.debug("removeCN2alias: " + cn + "<->" + alias);
      }
      commonName2alias.remove(cn);
    }

  
  /** Set a key entry in the keystore */
  public  void setKeyEntry(String alias, 
                           PrivateKey privatekey,
			   X509Certificate[] certificate)  {
    
    if (log.isDebugEnabled()) {
      log.debug("Setting keystore private key entry:" + alias);
    }
    addCN2alias(alias, certificate[0]);
    try {
      synchronized(keystore) {
        keystore.setKeyEntry(alias, privatekey, param.keystorePassword,
                             certificate);
      }
    } catch(Exception e) {
      if (log.isErrorEnabled()) {
        log.error("Unable to set key entry in the keystore - "
                  + e.getMessage());
      }
    }
    // Store key store in permanent storage.
    storeKeyStore();
  }

  private void setCertificateEntry(String alias, X509Certificate aCertificate)  {
    
    if (log.isDebugEnabled()) {
      log.debug("Setting keystore certificate entry:" + alias);
    }
    addCN2alias(alias, aCertificate);
    try {
      synchronized(keystore) {
        keystore.setCertificateEntry(alias, aCertificate);
      }
    } catch(Exception e) {
      if (log.isErrorEnabled()) {
        log.error("Unable to set certificate in the keystore - "
                  + e.getMessage());
      }
    }
    // Store key store in permanent storage.
    storeKeyStore();
  }

 

  public void deleteEntry(String alias, String commonName)  {

    removeCN2alias(commonName);
    try {
      keystore.deleteEntry(alias);
    } catch(Exception e) {
      if (log.isErrorEnabled()) {
        log.error("Unable to set certificate in the keystore - "
                  + e.getMessage());
      }
    }

    // Store key store in permanent storage.
    storeKeyStore();
  }

  /** Store the keystore in permanent storage. Should be called anytime
      a key is modified, created or deleted. */
  private void storeKeyStore()  {

    if (log.isDebugEnabled()) {
      log.debug("Storing keystore in permanent storage");
    }
    try {
      FileOutputStream out = new FileOutputStream(param.keystorePath);
      synchronized(keystore){
        keystore.store(out, param.keystorePassword);
        out.flush();
      }
      out.close();
    } catch(Exception e) {
      if (log.isErrorEnabled()) {
        log.error("Can't flush the certificate to the keystore--"
                  + e.getMessage());
      }
    }
  }

  public  X509Certificate getCertificate(String alias)throws KeyStoreException {

    X509Certificate certificate =
      (X509Certificate)keystore.getCertificate(alias); 
    return certificate;
  }
  
  public PrivateKey getKey(String alias) throws KeyStoreException,
    NoSuchAlgorithmException,
    UnrecoverableKeyException {

    PrivateKey privatekey = null;
    synchronized(keystore) {
      privatekey= (PrivateKey) keystore.getKey(alias, param.keystorePassword);
    }
    return privatekey;
  }

  public void saveCertificateInTrustedKeyStore(X509Certificate aCertificate,
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

    for (Iterator it = trustListeners.iterator(); it.hasNext(); ) {
      TrustManager tm = (TrustManager)it.next();
      tm.updateKeystore();
    }
  }

  public void addTrustListener(TrustManager tm) {
    trustListeners.add(tm);
  }

  public X509Certificate[] getTrustedIssuers() {
    ArrayList list = new ArrayList();
    try {
      for (Enumeration e = caKeystore.aliases(); e.hasMoreElements(); ) {
        String alias = (String)e.nextElement();
        X509Certificate cert = (X509Certificate)caKeystore.getCertificate(alias);
        list.add(cert);
      }
    } catch (Exception e) {
      log.warn("Error: can't get the certificates from truststore. " + e.toString());
    }

    X509Certificate[] trustedcerts = new X509Certificate[list.size()];
    for (int i = 0; i < list.size(); i++)
      trustedcerts[i] = (X509Certificate)list.get(i);
    return trustedcerts;
  }

  public void setKeyEntry(String alias, 
                          PrivateKey privatekey,char[] pwd,
			  Certificate[] certificate) throws KeyStoreException  {
    
    if(keystore==null) {
      log.debug(" keystore is null:");
    }
    synchronized(keystore) {
      keystore.setKeyEntry(alias, privatekey, pwd, certificate);
    }
  }

  public  Certificate[] getCertificateChain(String alias)throws KeyStoreException  {
    
    return keystore.getCertificateChain(alias);
  }

  public PrivateKey getKey(String alias, char[] pwd) throws KeyStoreException,
    NoSuchAlgorithmException,
    UnrecoverableKeyException  {
    return(PrivateKey) keystore.getKey(alias,pwd);
  }
  
  public String getKeyStorePath() {
    return param.keystorePath;
  }
  
  public String getCaKeyStorePath() {
    return param.caKeystorePath;
  }

  public void publishDNtoBB( String dname) {
   
    if(log.isDebugEnabled()) {
      log.debug(" publishDNstoBB(dname ) ");
    } 
    if((_threadService ==null) || (_blackboardService ==null) || (dname == null)) {
      if(log.isDebugEnabled()) {
        log.debug(" In publishDNstoBB(dname ) either blackboard service or thread service  or dn name is null ");
      }
      return;
    }
    final String dnName=dname;
    Schedulable dnPublisherThread = _threadService.getThread(CertificateCache.this, new Runnable( ) {
        public void run(){
          _blackboardService.openTransaction();
          _blackboardService.publishAdd(new InUseDNObject(dnName));
          try {
            _blackboardService.closeTransaction() ;
          }
          catch(SubscriberException subexep) {
            log.warn(" Unable to publish  in InUseDNObject :"+ subexep.getMessage());
            return;
          }
        }
      },"DNPublisherThread");
    dnPublisherThread.start();
  }
 
  public void createEvents() {
    if(log.isDebugEnabled()) {
      log.debug(" createevents called from MyServiceAvailableListener");
    }
    _eventService = (EventService)serviceBroker.getService(this,
                                                           EventService.class,
                                                           null);
    if (_eventService == null || !_eventService.isEventEnabled()) {
      return;
    }
    Enumeration e = certsCache.keys();
    while (e.hasMoreElements()) {
      String name = (String) e.nextElement();
      List list = (List) certsCache.get(name);
      ListIterator it = list.listIterator();
      while (it.hasNext()) {
        CertificateStatus cs = (CertificateStatus) it.next();
        if(cs!=null) {
          if(cs.getCertificateType()==CertificateType.CERT_TYPE_CA){
            X509Certificate cert=cs.getCertificate();
            if(cert!=null) {
              sendEvent(cert.getSubjectDN().getName());
              break;
            }
            else {
              log.warn("get certifcate with cs returned null for dn increateEvents  ="+name);
            }
          }
        }
      }
    }
  }
  public void publishDNstoBB(){
    if(log.isDebugEnabled()) {
      log.debug(" publishDNstoBB called from MyServiceAvailableListener");
    }
    _threadService= (ThreadService)serviceBroker.getService(this,
                                                            ThreadService.class,
                                                            null);
    _blackboardService = (BlackboardService)serviceBroker.getService(this,
                                                                     BlackboardService.class,
                                                                     null);
    if((_threadService!=null)&&(_blackboardService != null) && (!initPublishDN)){
      Enumeration e = certsCache.keys();
      while (e.hasMoreElements()) {
        String name = (String) e.nextElement();
        List list = (List) certsCache.get(name);
        ListIterator it = list.listIterator();
        while (it.hasNext()) {
          CertificateStatus cs = (CertificateStatus) it.next();
          if(cs!=null) {
            if(cs.getCertificateType()==CertificateType.CERT_TYPE_CA){
              X509Certificate cert=cs.getCertificate();
              if(cert!=null) {
                publishDNtoBB(cert.getSubjectDN().getName());
                break;
              }
              else {
                log.warn("get certifcate with cs returned null for dn ="+name);
              }
            }
          }
          else {
            log.warn("Certificate Status is null for :"+ name);
          }
        }//end of  while (it.hasNext())
      }//end of  while (e.hasMoreElements())
       
      initPublishDN =true; 

    }// end of if((_threadService!=null)&&(_blackboardService != null) && (!initPublishDN))
  }

  public void updateCRLCache()  {
    
    log.debug(" UpdateCRLCache called from MyServiceAvailableListener");
    if (_crlCacheService == null) {
      _crlCacheService=(CRLCacheService)
        serviceBroker.getService(this, CRLCacheService.class, null);
    }
    Enumeration e = certsCache.keys();
    while (e.hasMoreElements()) {
      String name = (String) e.nextElement();
      List list = (List) certsCache.get(name);
      ListIterator it = list.listIterator();
      log.debug("Updating CRL Cache for: " + name);
      while (it.hasNext()) {
        CertificateStatus cs = (CertificateStatus) it.next();
        if(cs!=null) {
          if(cs.getCertificateType()==CertificateType.CERT_TYPE_CA){
            if(_crlCacheService!=null) {
              X509Certificate cert=cs.getCertificate();
              if(cert!=null) {
                _crlCacheService.addToCRLCache(cert.getSubjectDN().getName());
                break;
              }
              else {
                log.warn("get certifcate with cs returned null for dn ="+name);
              }
            }
            else {
              log.warn("CRL cache is null.. though MyServiceAvailableListener was called :");
            }
          }
        }
        else {
          log.warn("Certificate Status is null for :"+ name);
        }
      }
    }
  }

  public synchronized String getBlackboardClientName() {
    
    if (blackboardClientName == null) {
      StringBuffer buf = new StringBuffer();
      buf.append(getClass().getName());
      blackboardClientName = buf.toString();
    }
    return blackboardClientName;
  }

  public long currentTimeMillis() {
    if(_alarmService == null) {
      _alarmService= (AlarmService)serviceBroker.getService(this,
                                                            AlarmService.class,
                                                            null);
    }
    if (_alarmService != null)
      return _alarmService.currentTimeMillis();
    else
      return System.currentTimeMillis();
  }

  public void setEventService(EventService service) {
    _eventService = service;
  }

  private void sendEvent(String dn) {
    if((_eventService == null) || (!_eventService.isEventEnabled()) || (myAddress ==null)) {
      return;
    }
    
    _eventService.event("[STATUS] CADNAddedToCertCache(" +
                        myAddress.toAddress() +
                        ") DN(" +
                        dn +
                        ")");

  }

  public void event(String evt) {
    if(_eventService == null || !_eventService.isEventEnabled()) {
      return;
    }
    _eventService.event(evt);
  }

  private class MyServiceAvailableListener implements ServiceAvailableListener{
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      if(log.isDebugEnabled()) {
        log.debug(" MyServiceAvailableListener listener called for service :"+ sc.getName());
      }
      if( CRLCacheService.class.isAssignableFrom(sc)) {
	if (log.isInfoEnabled()) {
	  log.info("CRL Cache Service is available now in Certificate Cache going to call updateCRLCache");
	}
        if(_crlCacheService == null) {
          updateCRLCache();	
        }
      }
      if(BlackboardService.class.isAssignableFrom(sc)) {
	if (log.isInfoEnabled()) {
	  log.info("Black board Service is available now in Certificate Cache going to publish used CA DNS ");
	}
        if(_blackboardService == null) {
          publishDNstoBB();
        }
      }
      if(ThreadService.class.isAssignableFrom(sc)) {
	if (log.isInfoEnabled()) {
	  log.info("Thread Service is available now in Certificate Cache going to publish used CA DNS ");
	}
        if(_threadService == null) {
          publishDNstoBB();
        }
      }
      if(EventService.class.isAssignableFrom(sc)) {
	if (log.isInfoEnabled()) {
	  log.info("Event Service is available now in Certificate Cache going to publish used CA DNS ");
	}
        if(_eventService == null) {
          createEvents();
        }
      }
      if ( (sc == AgentIdentificationService.class) &&(myAddress==null) ) {
	if (log.isInfoEnabled()) {
	  log.info(" AgentIdentification Service is available now in Certificate Cache");
	}
        AgentIdentificationService ais = (AgentIdentificationService)
          serviceBroker.getService(this, AgentIdentificationService.class, null);
        if(ais!=null){
          myAddress = ais.getMessageAddress();
          createEvents();
        }
        serviceBroker.releaseService(this, AgentIdentificationService.class, ais);
      }
    }
  }
  
  

}
