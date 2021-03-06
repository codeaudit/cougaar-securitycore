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


package org.cougaar.core.security.crypto;

import java.io.IOException;
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Vector;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crlextension.x509.extensions.CertificateIssuerExtension;
import org.cougaar.core.security.crlextension.x509.extensions.IssuingDistributionPointExtension;
import org.cougaar.core.security.naming.CertificateEntry;
import org.cougaar.core.security.naming.NamingCertDirectoryServiceClient;
import org.cougaar.core.security.policy.CertificateAttributesPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.services.crypto.CRLCacheService;
import org.cougaar.core.security.services.crypto.CertValidityService;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.CertificateRequestorService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.CACertDirectoryService;
import org.cougaar.core.security.services.util.CertificateSearchService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.ssl.KeyManager;
import org.cougaar.core.security.ssl.ServerKeyManager;
import org.cougaar.core.security.ssl.UserKeyManager;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.KeyUsageExtension;
import javax.net.ssl.X509KeyManager;
import sun.security.x509.OIDMap;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;

/** A common holder for Security keystore information and functionality
 */
final public class KeyRing  implements KeyRingService  {
  // keystore stores private keys and well-know public keys
  // private DirectoryKeyStore directoryKeystore;
  private CertificateSearchService search;
  private CertificateRequestorService certRequestor;
  private NamingCertDirectoryServiceClient namingService;
  /*
    private SearchServiceParameters searchParam;
    private DirectoryKeyStoreParameters param;
  */
  private boolean debug = false;
  private PrivateKeyPKCS12 pkcs12;
  private SecurityPropertiesService secprop = null;
  private ServiceBroker serviceBroker;
  private ConfigParserService configParser = null;
  private static Logger log;
  private CertificateCacheService cacheservice=null;
  /*
    private boolean isCertAuth=false;
    private boolean isRootCA=false;
  */
  private String role;
  private CryptoClientPolicy cryptoClientPolicy;
  //private DirContext namingContext = null;


  private List       _initKeyManager = new LinkedList();
  private boolean    _initializing = true;

  /*
    private static final String CDTYPE_ATTR = "CertDirectoryType";
    private static final String CDURL_ATTR = "CertDirectoryURL";
    private static final String CERT_DIR = "/Certificates";
  */


  /** Cache for getNamingAttributes
   */
  //private Hashtable _namingAttributesCache = new Hashtable();

  /**
   * Cache for CA to store key pair request that is blocked because CA
   * key has not been generated yet. Key will be generated and cache
   * will be cleared after CA key has been generated.
   */
  private Hashtable requestedIdentities = new Hashtable();
  private boolean _requestingIdentities = false;

  /**
   * For introducing stress to be able to use expired certificate to test the system
   */
  private List ignoredList = new ArrayList();

  static {
    log = LoggerFactory.getInstance().createLogger(KeyRing.class);
    try {
      OIDMap.addAttribute("x509.info.extensions.IssuingDistibutionPoint",
			  "2.5.29.28",
                          IssuingDistributionPointExtension.class);
    }
    catch(CertificateException certexp) {
      if (log.isErrorEnabled()) {
	log.error(" Could not add OID Mapping :" + certexp.getMessage());
      }
    }
    Pattern p = Pattern.compile("(\\d+)\\.(\\d+)\\.(\\w+)");
    Matcher m = p.matcher(System.getProperty("java.version"));
    int jvm_version = 0;
    if (m.matches()) {
       jvm_version = Integer.parseInt(m.group(2));
    }
    if (jvm_version < 5) {
      try {
        OIDMap.addAttribute("x509.info.extensions.CertificateIssuer",
                            "2.5.29.29",
                            CertificateIssuerExtension.class);
      }
      catch(CertificateException certexp) {
        if (log.isErrorEnabled()) {
          log.error(" Could not add OID Mapping :" + certexp.getMessage());
        }
      }
    }
  }

  public KeyRing(ServiceBroker sb) {
    serviceBroker = sb;
    init();
  }

  private void init() {
    //log.debug(" Service broker available at Key Ring is:"+ serviceBroker.toString());
    secprop = (SecurityPropertiesService)serviceBroker.getService(this,
								  SecurityPropertiesService.class,
								  null);
    configParser = (ConfigParserService)serviceBroker.getService(this,
								 ConfigParserService.class,
								 null);
    if (secprop == null) {
      throw new RuntimeException("unable to get security properties service");
    }
    if (configParser == null) {
      throw new RuntimeException("unable to get config parser service");
    }

    role =secprop.getProperty(SecurityPropertiesService.SECURITY_ROLE);
    if (role == null && log.isInfoEnabled() == true) {
      log.info("Role is not defined");
    }
    SecurityPolicy[] sp = configParser.getSecurityPolicies(CryptoClientPolicy.class);
    cryptoClientPolicy = (CryptoClientPolicy) sp[0];
    //isRootCA=cryptoClientPolicy.isRootCA();

    if (cryptoClientPolicy == null
	|| cryptoClientPolicy.getCertificateAttributesPolicy() == null) {
      // This is OK for standalone applications if they don't plan to use
      // certificates for authentication, but it's not OK for nodes
      boolean exec =
	Boolean.valueOf(System.getProperty("org.cougaar.core.security.isExecutedWithinNode")).booleanValue();
      if (exec == true) {
	log.warn("Unable to get crypto Client policy");
      }
      else {
	log.info("Unable to get crypto Client policy");
      }
      throw new RuntimeException("Unable to get crypto Client policy");
    }

    //searchParam=new SearchServiceParameters();
    /*
      param = new DirectoryKeyStoreParameters();
      param.serviceBroker = serviceBroker;
    */

    // LDAP certificate directory
    boolean isCertAuth = cryptoClientPolicy.isCertificateAuthority();

    TrustedCaPolicy[] trustedCaPolicy = cryptoClientPolicy.getTrustedCaPolicy();

    if (trustedCaPolicy.length > 0) {
      if (log.isDebugEnabled()) {
	log.debug(" TrustedCaPolicy is  :"+ trustedCaPolicy[0].toString());
      }
      /*
        searchParam.ldapServerUrl = trustedCaPolicy[0].certDirectoryUrl;
        searchParam.ldapServerType = trustedCaPolicy[0].certDirectoryType;
      */
    }
    else {
      if (log.isDebugEnabled()) {
	log.debug(" TrustedCaPolicy is Empty ! ");
      }

    }

    /* check if cert auth shoul initilize some ne class
     */
    if(isCertAuth) {
      if (log.isDebugEnabled()) {
	log.debug(" is Cert  Authority ----------------------------------------:");
      }

      X500Name [] caDNs=configParser.getCaDNs();
      if (caDNs.length > 0) {
        /*
          String caDN=caDNs[0].getName();
          CaPolicy capolicy=configParser.getCaPolicy(caDN);
          searchParam.ldapServerUrl =capolicy.ldapURL;
          searchParam.ldapServerType =capolicy.ldapType;
          searchParam.defaultCaDn = caDN;
        */
      }
      else {
	log.debug(" caDNs is empty !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!-:"+ caDNs.length);
      }
    }
    /*
      if (log.isDebugEnabled()) {
      log.debug(" Ladap type is :"+ searchParam.ldapServerType);
      }
    */

    //search=new SearchServiceImpl(searchParam,serviceBroker);
    cacheservice=(CertificateCacheService)serviceBroker.getService(this,
                                                                   CertificateCacheService.class,
                                                                   null);
    if(cacheservice==null) {
      log.warn("Cache service is null in init of KeyRing Service");
    }

    search = (CertificateSearchService) serviceBroker.getService(this,
                                                                 CertificateSearchService.class,
                                                                 null);
    //certRequestor=new CertificateRequestor(serviceBroker,configParser,role);
    certRequestor = (CertificateRequestorService)serviceBroker.getService(this,
        CertificateRequestorService.class,
        null);
    if (certRequestor == null) {
      if (log.isDebugEnabled()) {
        log.debug("adding service listener for Certificate Requestor");
      }
      ServiceAvailableListener listener = new ListenForServices();
      serviceBroker.addServiceListener(listener);      
    }

    namingService = new NamingCertDirectoryServiceClient(serviceBroker);
    //directoryKeystore = new DirectoryKeyStore(param);
    pkcs12 = new PrivateKeyPKCS12( serviceBroker);
    if ( pkcs12 == null && isCertAuth == false) {
      // Cannot proceed without keystore
      boolean exec =
	Boolean.valueOf(System.getProperty("org.cougaar.core.security.isExecutedWithinNode")).booleanValue();
      if (exec == true) {
	log.error("Cannot continue secure execution without cryptographic data files");
      }
      else {
	log.info("Cryptographic keystores are missing");
      }
      throw new RuntimeException("No cryptographic keystores");
    }
    setCertificateTrustInCache();

    // Now start CACertDirectoryService
    // update CA cert information from blackboard, and update naming service
    if (isCertAuth) {
      CACertDirectoryService caOperations = (CACertDirectoryService)
	serviceBroker.getService(this,CACertDirectoryService.class, null);
      serviceBroker.releaseService(this, CACertDirectoryService.class, caOperations);
    }
  }

  private class ListenForServices implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      final ServiceBroker sb = ae.getServiceBroker();
      if ( (sc == CertificateRequestorService.class) &&(certRequestor==null) ) {
        if(log.isInfoEnabled()){
          log.info("CertificateRequestorService is available now.");
        }
        certRequestor = (CertificateRequestorService)
          serviceBroker.getService(this, CertificateRequestorService.class, null);
        if (certRequestor != null) {
        }
      }
    }
  }

  public synchronized void setKeyManager(X509KeyManager theKm) {
  	KeyManager km = (KeyManager)theKm;
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
            // CA cert will be published after rehydration from BB
            /*
            if (cs.getCertificateType() == CertificateType.CERT_TYPE_CA) {
              // update to naming
              updateNS(name);
            }
            */
	  }
	} // END while(it.hasNext())
	if (isTrusted == false) {
	  if (log.isDebugEnabled()) {
	    log.debug("No trusted certificate was found for " + name.toString());
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
        // get CA certificate if it is not yet obtained
        certRequestor.generateKeyPair(name,true,null);
        // update to naming
        //updateNS(name);
      } catch (Exception ex) {
        log.warn("Exception in initCertCache.getNodeCert: " + ex.toString());
      }
    }
  }

  public boolean setCertificateTrust(X509Certificate certificate, CertificateStatus cs,
				     X500Name name, Hashtable selfsignedCAs) {
    boolean isTrusted = false; // Raise a warning if there is no trusted cert for that entity.

    try {
      X509Certificate[] certs = checkCertificateTrust(certificate);
      // Could establish a certificate chain. Certificate is trusted.
      // Update Certificate Status.
      if (log.isDebugEnabled()) {
        log.debug("Certificate chain established for " + certificate.getSubjectDN().getName());
      }
      cs.setCertificateTrust(CertificateTrust.CERT_TRUST_CA_SIGNED);
      cs.setCertificateChain(certs);
      if(cacheservice!=null){
	cacheservice.updateBigInt2Dn(certificate, true);
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
	if (!cryptoClientPolicy.isRootCA() && cryptoClientPolicy.isCertificateAuthority()) {
	  // We are a subordinate CA
	  if (cs.getCertificateType() == CertificateType.CERT_TYPE_CA) {
	    // should this be moved to after initialization?
            String cn = cacheservice.getCommonName(name);
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

  public X509Certificate[] checkCertificateTrust(
    X509Certificate [] acertificate)
    throws CertificateChainException, CertificateExpiredException,
    CertificateNotYetValidException, CertificateRevokedException {
    if (acertificate.length == 1) {
      return checkCertificateTrust(acertificate[0]);
    }
    return checkCertificateTrust(acertificate, false);
  }

  public X509Certificate[] checkCertificateTrust(
    X509Certificate certificate)
    throws CertificateChainException, CertificateExpiredException,
    CertificateNotYetValidException, CertificateRevokedException
    {
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
      boolean ok = buildChain(certificate, vector, true);
      X509Certificate acertificate[] = new X509Certificate[vector.size()];
      if (ok) {
        // the list returned by buildChain is a reversed chain list!
        for (int i = 0; i < acertificate.length; i++) {
          acertificate[i] = (X509Certificate)vector.get(acertificate.length-i-1);
        }
        checkCertificateTrust(acertificate, true);
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

  private boolean isIgnoredCertificate(X509Certificate c) {
    String cname = null;
    try {
      cname = new X500Name(c.getSubjectDN().toString()).getCommonName();
    } catch (IOException iox) {}
    if (log.isDebugEnabled()) {
      log.debug("Certificate Expired :" + cname);
    }  
    if (cname != null && ignoredList.contains(cname)) {
      if (log.isWarnEnabled()) {
        log.warn("Ignoring the expired certificate " + c);
      }
      return true;
    }
    return false;
  }

  /* if a full certificate chain is received, no need to build chain,
     this function takes both single cert and an unvalidated chain.
  */
  private X509Certificate[] checkCertificateTrust(
    X509Certificate [] acertificate, boolean isValidated)
    throws CertificateChainException, CertificateExpiredException,
    CertificateNotYetValidException, CertificateRevokedException
    {
      boolean isTrusted = false;
      if (!isValidated) {
        try {
          // need to verify chain if it is not build using buildchain
          validateReply(null, acertificate[0], acertificate);
        } catch (CertificateException cex) {
          throw new CertificateChainException(cex.toString(), CertificateTrust.CERT_TRUST_UNKNOWN);
        }
      }
      else {
        isTrusted = true;
      }

      for(int i = acertificate.length - 1; i >= 0; i--) {
        // Check certificate validity
try {
        ((X509Certificate) acertificate[i]).checkValidity();
} catch (CertificateExpiredException cee) {
  if (!isIgnoredCertificate((X509Certificate)acertificate[0])) {
    throw cee;
  }
}
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
              || keyusage.getBits().length < KeyManagementConstants.KEYUSAGE_CERT_SIGN_BIT
              || !keyusage.getBits()[KeyManagementConstants.KEYUSAGE_CERT_SIGN_BIT]) {
            log.warn("Certificate does not have signing capability."
                     + acertificate[i].getSubjectDN().getName());
            throw new CertificateChainException("Certificate does not have signing capability.",
                                                CertificateTrust.CERT_TRUST_NOT_TRUSTED);

          }
        }
        // need to check whether one of the cert in the chain is revoked
        if (!isValidated) {
          if (cacheservice.checkRevokedCache(acertificate[i])) {
            throw new CertificateRevokedException("Certificate is revoked: "
                                                  + acertificate[i].getSubjectDN().getName());
          }

          // then check whether any signer is trusted
          String signerName = acertificate[i].getSubjectDN().getName();
          try {
            X500Name x500signer = new X500Name(signerName);
            List listSigner = getValidCertificates(x500signer);
            if (listSigner == null || listSigner.size() == 0) {
              isTrusted = true;
            }
          } catch (IOException iox) {
            throw new CertificateChainException("Not a valid signer: " + signerName,
                                                CertificateTrust.CERT_TRUST_UNKNOWN);
          }
        }
      }

      if (!isTrusted) {
        throw new CertificateChainException("No trusted signer found for " +
                                            acertificate[0].getSubjectDN().getName(), CertificateTrust.CERT_TRUST_UNKNOWN);
      }
      return acertificate;
    }


  /** Build a certificate chain.
   *  On output, vector contains an array of certificates leading to
   *  a trusted Certificate Authority, starting with the certificate itself.
   *  Returns true if we could build a chain.
   *  If any
   */
  private boolean buildChain(X509Certificate x509certificate, Vector vector, boolean checkValidity)  {

    boolean ret = internalBuildChain(x509certificate, vector, false, checkValidity);
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
				     boolean checkValidity)  {
    Principal principal = x509certificate.getSubjectDN();
    Principal principalSigner = x509certificate.getIssuerDN();
    List listSigner=null;
    if (log.isDebugEnabled()) {
      log.debug("Build chain: " + principal.getName());
    }

    if(cacheservice==null) {
      log.warn("Unable to get Certificate Cache service :");
    }

    X500Name x500NameSigner = CertificateUtility.getX500Name(principalSigner.getName());
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
      if (cs != null && cs.getCertificateType() == CertificateType.CERT_TYPE_CA) {
	// This is a trusted certificate authority.
	signedByAtLeastOneCA = true;
      }
      if (cryptoClientPolicy.isCertificateAuthority() && cryptoClientPolicy.isRootCA()) {
	// If DirectoryKeyStore is used in the context of a Certificate
	// Authority, then a self-signed certificate is OK.
	// Self-signed certificate should only be valid if it is type CA
	String title = CertificateUtility.findAttribute(principalSigner.getName(), "t");
	if (title != null && !title.equals(CertificateCacheConstants.CERT_TITLE_CA)) {
	  return false;
	}
	else{
	  return true;
	}
      }
      else {
	return signedByAtLeastOneCA;
      }
    }
    if (listSigner == null) {
      if (log.isDebugEnabled()) {
	log.debug("Cache has not been filled for this certificate");
	log.debug("Refreshing the cache for this certificate");
      }
      if (!signedByAtLeastOneCA) {
        if (log.isDebugEnabled()) {
          log.debug("Looking up certificate in directory service");
        }

        searchCert(x500NameSigner);
      }
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
      if(internalBuildChain(x509certificate1, vector, signedByAtLeastOneCA, checkValidity)) {
	vector.addElement(x509certificate);
	return true;
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("No valid signer key");
    }
    return signedByAtLeastOneCA;

  }

  /*
    this method is no longer used


    public DirectoryKeyStore getDirectoryKeyStore() {
    return directoryKeystore;
    }
  */

  public List findPrivateKey(String cougaarName) {
    return findPrivateKey(cougaarName, true);
  }

/** Lookup a private key given a Cougaar name.
 *  Currently, the Cougaar name is the common name.
 */
  public List findPrivateKey(String cougaarName, boolean validOnly) {

    // getX500DN only works for agent/node/server, does not work for CA and user
    if(cacheservice==null) {
      log.warn(" Unable to get Certificate Cache service in findPrivateKey");
      return null;
    }

	List certList = new ArrayList();
//    if (cryptoClientPolicy.isCertificateAuthority()) {
      List nameList = cacheservice.getX500NameFromNameMapping(cougaarName);
      if (nameList != null && nameList.size()> 0) {
	for (int i = 0; i < nameList.size(); i++) {
	  X500Name dname = (X500Name)nameList.get(i);
          List pkey = findPrivateKey(dname, validOnly);
          if (pkey != null) {
	    certList.addAll(pkey);
          }
	}
	return certList;
      }
      // else no cert has been created
      return certList;
/*
    }
    return findPrivateKey(CertificateUtility.getX500Name( getX500DN(cougaarName)), validOnly);
*/
  }

  public PrivateKey findPrivateKey(final X509Certificate cert) 
  {
    return findPrivateKey(cert, true);
  }

  private PrivateKey findPrivateKey(final X509Certificate cert, boolean warn)
  {
    try {
      X500Name x500Name = new X500Name(cert.getSubjectDN().getName());
      final String name = x500Name.getCommonName();

      // relieve messages to naming, for local keys
      // do not need to go to naming
      List nameList = getX500NameFromNameMapping(name);
      Iterator iter = nameList.iterator();
      while (iter.hasNext()) {
        X500Name dname = (X500Name) iter.next();
        List pkCerts = findPrivateKey(dname);
        if (pkCerts == null) {
          throw new Exception("No private key found.");
        }
        Iterator jter = pkCerts.iterator();
        while (jter.hasNext()) {
          PrivateKeyCert pkc = (PrivateKeyCert) jter.next();
          if (cert.equals(pkc.cert.getCertificate())) {
            return pkc.pk;
          }
        }
      }
      if (warn && log.isWarnEnabled()) {
        log.warn("Unable to get private key of " +
                 cert + " -- does not exist.");
      }
    } catch (Exception e) {
//      if (warn && log.isWarnEnabled()) {
      if (log.isInfoEnabled()) {
        // Richard, the original warning is confusing, it claims dn is not
        // well-formed but actually it is catching the excpetion thrown in
        // "No private key found"
        // Also throwing a warning with stack trace so deep in the code
        // messes up logs.
        log.info("Unable to get private key of " +
                 cert + ", " + e);
      }
    }
    return null;
  }

  public boolean checkPrivateKey(final CertificateStatus certStatus)
  {
    return findPrivateKey(certStatus.getCertificate(), false) != null;
  }

  public List findPrivateKey(X500Name x500name) {
    return  findPrivateKey(x500name,true);
  }

  private  List findPrivateKey(X500Name x500Name, boolean validOnly) {
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("readPrivateKey"));
    }

    if (log.isDebugEnabled()) {
      log.debug("get Private key for " + x500Name + ". ValidOnly=" + validOnly);
    }
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


  public List getValidPrivateKeys(X500Name x500Name) {
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


  private boolean checkCertificate(CertificateStatus cs) {
    return checkCertificate(cs, false, false);
  }

  /** Check the certificate validity of a certificate.
   */
  public boolean checkCertificate(CertificateStatus cs,
				  boolean buildChain, boolean changeStatus) {
    boolean isTrustedAndValid = false;

/*
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
*/

    // The first element in the list should be the most up-to-date
    // certificate. However, there are some cases where it may not.
    // For instance, we may have just received a new certificate from the CA,
    // but it is not yet valid and we still have another certificate
    // which is still valid.
    if (cs == null) {
      throw new IllegalArgumentException("CertificateStatus is null");
    }
    try {
      // TODO: no need to build chain again here, chain is already in status
try {
      cs.checkCertificateValidity();
} catch (CertificateExpiredException cee) {
  if (!isIgnoredCertificate((X509Certificate)cs.getCertificate())) {
    throw cee;
  }
}

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
          if (log.isInfoEnabled()) {
            log.info("One of signers in chain has been revoked." 
              + cs.getCertificate().getSubjectDN().getName());
          }
          cs.setCertificateTrust( CertificateTrust. CERT_TRUST_REVOKED_CERT);
        }
      }

    }
    return isTrustedAndValid;
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

  private Object findCertLock = new Object();
//  public synchronized  List findCert(X500Name dname,
  public List findCert(X500Name dname,
                       int lookupType, 
                       boolean validOnly)
  {
    // findCert is called very frequently
    // we should not place a lock on the KeyRing class itself,
    // if we lock on findCert itself we only need to iliminate
    // circular lock on findCert.
    synchronized (findCertLock) {
      ArrayList certificateList = new ArrayList(0);
      if(cacheservice==null) {
        log.warn(" Unable to get Certificate cache service in findCert");
        return null;
      }
      String commonName = cacheservice.getCommonName(dname);

      cacheservice.getX500NameFromNameMapping(commonName);
      boolean inNameMapping = cacheservice.presentInNameMapping(dname);
      if (!inNameMapping) {
        if (log.isDebugEnabled()) {
          log.debug("DirectoryKeyStore.findCert(" + dname.toString()
                    + ") - x500 Name = not assigned yet" + lookupType);
        }
      }
      if ((lookupType & KeyRingService.LOOKUP_FORCE_LDAP_REFRESH) != 0
	  || (lookupType & KeyRingService.LOOKUP_LDAP) != 0) {
	if (log.isDebugEnabled()) {
	  log.debug("Retrieving LDAP client");
	}
	//certFinder = getCertDirectoryServiceClient(dname);
      }

      // Refresh from LDAP service if requested
      if (((lookupType & KeyRingService.LOOKUP_FORCE_LDAP_REFRESH) != 0)
	  || !inNameMapping) {
	if (log.isDebugEnabled()) {
	  log.debug("Looking up certificate in LDAP");
	}
	// Update cache with certificates from LDAP.
	//String filter = "(cn=" + commonName + ")";
        /*
          String filter = parseDN(dname.getName());
          lookupCertInLDAP(filter, certFinder);
        */
        searchCert(dname);

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

      List certList = internalFindCert(dname, lookupType, validOnly);

      if (certList == null) {
	return certificateList;
      }

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
      return  certificateList;
    }
  }

  private List internalFindCert(X500Name x500name,
				int lookupType,
				boolean validOnly) {
    // Search in the local hash map.
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
      log.debug("Search key in local hash table:" + x500name
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
          /*
            String filter = parseDN(x500name.getName());
            lookupCertInLDAP(filter, certFinder);
          */
          searchCert(x500name);
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

  public List findCert(String cougaarName) {
    List certificateList = null;
    try {
      certificateList =	findCert(cougaarName, KeyRingService.LOOKUP_KEYSTORE | KeyRingService.LOOKUP_LDAP);
    }
    catch (Exception e) {
      log.warn("Unable to find certificate for " + cougaarName + ". Reason:" + e);
    }
    return certificateList;

  }

  /**
   * @param cougaarName The common name of the entity
   * @param lookupType  The type of lookup.
   *  One of LOOKUP_LDAP, LOOKUP_KEYSTORE and LOOKUP_FORCE_LDAP_REFRESH
   */
  public List findCert(String cougaarName, int lookupType) {
    return findCert(cougaarName, lookupType, true);
  }

  /**
   * @param cougaarName The common name of the entity
   * @param lookupType  The type of lookup.
   *  One of LOOKUP_LDAP, LOOKUP_KEYSTORE and LOOKUP_FORCE_LDAP_REFRESH
   * @param validOnly   True: only valid certificates. False: all certificates
   */
  public List findCert(String cougaarName,
		       int lookupType, boolean validOnly) {
    if(log.isDebugEnabled()){
      log.debug("Looking for cougaar name " + cougaarName
		+ " type = " + lookupType);
    }
    if(cacheservice==null) {
      log.warn(" Unable to get Certificate Cache service in findCert");
      return null;
    }

    // This function does not work for normal node for multiple CA
    // if uses default certificate attribute
    //if (cryptoClientPolicy.isCertificateAuthority()) {
    List nameList = cacheservice.getX500NameFromNameMapping(cougaarName);
    if (nameList != null && nameList.size() > 0) {
      List certList = new ArrayList();
      for (int i = 0; i < nameList.size(); i++) {
        X500Name dname = (X500Name)nameList.get(i);
        certList.addAll(findCert(dname, lookupType, validOnly));
      }
      return certList;
    }
    // else no cert has been created
    return null;
  }

  /**
   * @return a Hashtable mapping String (CNAME) to CertificateStatus
   */
  public Hashtable findCertPairFromNS(String source, String target)
    throws CertificateException, IOException  {
    Hashtable certTable = findCertStatusPairFromNS(source, target, false);
    CertificateStatus srcStatus = (CertificateStatus)certTable.get(source);
    CertificateStatus tgtStatus = (CertificateStatus)certTable.get(target);
    certTable.put(source, srcStatus.getCertificate());
    certTable.put(target, tgtStatus.getCertificate());
    return certTable;
  }

  public Hashtable findCertStatusPairFromNS(String source, 
                                            String target,
                                            boolean sourceNeedsPrivateKey)
    throws CertificateException, IOException  
  {
    // Look in revisions before 1.83 for many commented out alternative 
    // 1implementations of this code


    // check whether agent has started yet, this fixes the problem where
    // LDAP is dirty and returning old certificates. If agent has started
    // and obtained new certificates it will update naming.
    if (log.isDebugEnabled()) {
      log.debug("findCertPairFromNS: " + source + " vs " + target);
    }

    Hashtable certTable = new Hashtable();

    // sometimes (at unzip & run startup) naming has not been updated yet
    // maybe able to find cert from local hash
    // however, cert from local hash needs to be refreshed once naming
    // update is finished, because local hash may not have the trusted
    // cert.

    // find if there is a path in target that is trusted
    // TODO: if there is multiple trusted path choose the shortest one

    // how deep is the trusted cert

    CertificateStatus cs = findOrRefreshCert(source,
                                             sourceNeedsPrivateKey);
    if (cs != null) {
      certTable.put(source, cs);
    }

    // if source and target is the same no need to redo the whole thing
    if (!source.equals(target) || cs == null) {
      cs = findOrRefreshCert(target, false);
      if (cs != null) {
        certTable.put(target, cs);
      }
    }
    else {
      certTable.put(target, cs);
    }

    if (certTable.get(source) == null || certTable.get(target) == null) {
      String errMsg = "Cannot find matching cert with same trust. " +
        "source: " + certTable.get(source) + " vs target: " + certTable.get(target);
      if (log.isDebugEnabled()) {
        log.debug(errMsg);
      }
      throw new CertificateException(errMsg);
    }

    return certTable;
  }

  private CertificateStatus findOrRefreshCert(String name,
                                              boolean requirePrivateKey) 
    throws IOException 
  {
    List nameList = null;
    int lookupFlags[] = { KeyRingService.LOOKUP_KEYSTORE |
                          KeyRingService.LOOKUP_LDAP,
                          KeyRingService.LOOKUP_KEYSTORE |
                          KeyRingService.LOOKUP_LDAP |
                          KeyRingService.LOOKUP_FORCE_LDAP_REFRESH };

      for (int j = 0; j < lookupFlags.length; j++) {
        if (j == 0) {
          nameList = getX500NameFromNameMapping(name);
        }
        else {
          nameList = findDNFromNS(name);
          // if certificate entry is not in naming then let the caller knows
          // the reason, this happens often at the beginning
          if (nameList.size() == 0) {
            throw new IOException("No CertificateEntry in naming for " + name + " yet");
          }
        }

        for (int i = 0; i < nameList.size(); i++) {
          X500Name dname = (X500Name)nameList.get(i);

          List certList = findCert(dname, lookupFlags[j], true);
          if (certList == null || certList.size() == 0) {
            continue;
          }
          for (Iterator certIt = certList.iterator();
               certIt.hasNext();) {
            CertificateStatus certStatus = (CertificateStatus) certIt.next();
            if (!requirePrivateKey || 
                checkPrivateKey(certStatus)) {
              return certStatus;
            }
          }
        }
      }
    return null;
  }


  public List findDNFromNS(String name) {
    /*
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
    */
    return search.findDNFromNS(name);
  }

/*
  private DirContext ensureCertContext() throws NamingException {
  // First, get the Naming service root context
  if (namingContext != null) {
  return namingContext;
  }

  NamingService namingSrv = (NamingService)
  serviceBroker.getService(this,
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
*/

  public X509Certificate[] findCertChain(X509Certificate c)  {
    X509Certificate[] chain = null;
    if (c == null) {
      return null;
    }
    try {
      chain = checkCertificateTrust(c);
    }
    catch (Exception e) {
    }
    return chain;
  }


  /*

  public Vector getCRL()
  {
  if (directoryKeystore == null) {
  return null;
  }
  return null;
  //return directoryKeystore.getCRL();
  }
  */


  /**
   * This function should only be used by non user or non CA
   * @return int status
   *  0-
   *  1-
   */

  public void  checkOrMakeCert(String commonName) {

    // this only happens in unzip & run, originally there is no trusted CA policy
    if (System.getProperty("org.cougaar.core.autoconfig", "false").equals("true")) {
      requestedIdentities.put(commonName, commonName);
      if (log.isDebugEnabled()) {
        log.debug("saving " + commonName + " to requested identity cache.");
      }
    }

    if (cryptoClientPolicy.isCertificateAuthority()) {
      X500Name dname = CertificateUtility.getX500Name(getX500DN(commonName));
      checkOrMakeCert(dname, false, null);
      return;
    }
    if(cacheservice==null) {
      log.warn("Unable to get Certificate cache Service in checkOrMakeCert");
    }
    String title=null;
    title=CertificateCache.getTitle(commonName);

    // go through all the trusted policies
    // more than one certificate may be acquired
    TrustedCaPolicy[] trustedCaPolicy = cryptoClientPolicy.getIssuerPolicy();

    // create a dummy host key so that https server can be started
    if (commonName.equals(NodeInfo.getHostName())) {
      try {
        CertificateAttributesPolicy cap = cryptoClientPolicy.getCertificateAttributesPolicy();
        X500Name dname = null;
	dname = new X500Name(CertificateUtility.getX500DN(commonName,title, cap));

        // only do this if there is no host key present
        if (cacheservice.findAlias(dname) == null) {
          if (log.isDebugEnabled()) {
            log.debug("Creating self signed host key");
          }
          if (certRequestor == null) {
            if (log.isWarnEnabled()) {
              log.warn("Failed to create host key - CertRequestor is not available",
                new Throwable());
            }
          }
          else {
            certRequestor.generateKeyPair(dname, false, cap);
          }
        }
      } catch (Exception ex) {
        if (log.isWarnEnabled()) {
          log.warn("Failed to create host key. ", ex);
        }
      }
    }

    if (trustedCaPolicy.length == 0) {
      if (log.isDebugEnabled()) {
        log.debug("There is no trusted policy yet.");
      }
    }

    for (int i = 0; i < trustedCaPolicy.length; i++) {
      CertificateAttributesPolicy cap = 
        cryptoClientPolicy.getCertificateAttributesPolicy(trustedCaPolicy[i]);
      X500Name dname = CertificateUtility.getX500Name(
        CertificateUtility.getX500DN(commonName,title, cap));
      checkOrMakeCert(dname, false, trustedCaPolicy[i]);
    }
  }

  /**
   * This function should only be used by user or CA identity request
   */
  public void checkOrMakeCert(X500Name dname, boolean isCACert) {
    checkOrMakeCert(dname, isCACert, null);
  }

  //public synchronized void checkOrMakeCert(X500Name dname, boolean isCACert, TrustedCaPolicy trustedCaPolicy) {
  private Object addKeyLock = new Object();

  public void checkOrMakeCert(X500Name dname, boolean isCACert, TrustedCaPolicy trustedCaPolicy) {

  if (log.isDetailEnabled()) {
    try {
      throw new Throwable();
    } catch (Throwable t) {
      log.detail("Stack : ", t);
    }
  }

    synchronized (addKeyLock) {
      if (log.isDebugEnabled()) {
        log.debug("CheckOrMakeCert: " + dname.toString() );
      }

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
            if (log.isDebugEnabled()) {
  	      log.debug("common name in checkOrMakeCert is :"+commonname);
            }
	  }
	  else {
            if (log.isDebugEnabled()) {
  	      log.debug("common name in checkOrMakeCert is :NULL");
             }
	  }

          if (commonname!=null && commonname.equals(NodeInfo.getNodeName())) {
          /* This functionality will be performed in KeyManagement
             CA only needs to be updated to NS
             if (cryptoClientPolicy.isCertificateAuthority()) {
             X500Name [] caDNs = configParser.getCaDNs();
             if (caDNs.length != 0) {
             publishCAToLdap(caDNs[0].getName());
             }
             }
          */
            updateNS(dname);
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
      PrivateKey privatekey = certRequestor.addKeyPair(dname, null,
                                                     isCACert, trustedCaPolicy);
      if (privatekey != null) {
        String commonname=cacheservice.getCommonName(dname);

        // notify validity listener
        CertValidityService validityService = (CertValidityService)
          serviceBroker.getService(this,
                                 CertValidityService.class,
                                 null);
        validityService.updateCertificate(commonname);
        serviceBroker.releaseService(this,
                                   CertValidityService.class,
                                   validityService);

      // only do it for node cert, otherwise will have infinite loop here
        if (commonname.equals(NodeInfo.getNodeName())) {
          updateNS(dname);
          handleRequestedIdentities(trustedCaPolicy);
        }
      }
      else {
        // if not succeeded, continue to the request in validity service
        CertValidityService validityService = (CertValidityService)
          serviceBroker.getService(this,
                                 CertValidityService.class,
                                 null);
        validityService.addCertRequest(dname, isCACert, trustedCaPolicy);
        serviceBroker.releaseService(this,
                                   CertValidityService.class,
                                   validityService);

      }
    }
  }


  private void handleRequestedIdentities(TrustedCaPolicy trustedCaPolicy) {
    // for unzip & run
    // after grabbing CA info from CA, plugin will request node
    // certificate
    // flag for unzip & run
    if (System.getProperty("org.cougaar.core.autoconfig", "false").equals("true")) {
      _requestingIdentities = true;
      for (Enumeration en = requestedIdentities.keys(); en.hasMoreElements(); ) {
        String cname = (String)en.nextElement();
        // no need to do dname again
        if (cname.equals(NodeInfo.getNodeName())) {
          continue;
        }
        X500Name dname = null;
        try {
          dname = new X500Name(CertificateUtility.getX500DN(cname,CertificateCache.getTitle(cname),
                                                            cryptoClientPolicy.getCertificateAttributesPolicy(trustedCaPolicy)));
        } catch (IOException iox) {}

        if (log.isDebugEnabled()) {
          log.debug("processing cert request for " + cname + " : " + dname);
        }

        checkOrMakeCert(dname, false, trustedCaPolicy);
        updateNS(dname);
      }

      requestedIdentities.clear();
      _requestingIdentities = false;
    }
  }

  public String findAlias(String commonName) {

    if(cacheservice==null) {
      log.warn(" Unabale to get Certificate cache service in findAlias");
    }
    return cacheservice.findAlias(CertificateUtility.getX500Name(getX500DN(commonName)));
  }


  /*
    this method needs to be modifed inoder to incorporate
    publishing CA to wp/yp or ldap
    private void publishCAToLdap(String caDN) {
    CertificateManagementService km = (CertificateManagementService)
    param.serviceBroker.getService(
    new CertificateManagementServiceClientImpl(caDN),
    CertificateManagementService.class,
    null);
    if (log.isDebugEnabled())
    log.debug("adding CA certificate to LDAP: " + caDN);
    }
  */


  public X509Certificate[] buildCertificateChain(X509Certificate certificate) {
    Vector vector = new Vector(2);
    boolean ok = buildChain(certificate, vector, false);
    X509Certificate acertificate[] = new X509Certificate[vector.size()];
    int i = 0;
    for(int j = vector.size() - 1; j >= 0; j--) {
      acertificate[i] = (X509Certificate)vector.elementAt(j);
      i++;
    }
    return acertificate;
  }


  public List getValidCertificates(X500Name x500Name)  {

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

  public String getAlias(X509Certificate clientX509) {
    String alias = null;

    if(cacheservice==null) {
      log.warn("Unable to get Certificate cache Service in getAlias");
    }
    try {
      String alg = "MD5"; // TODO: make this dynamic
      MessageDigest md = CertificateUtility.createDigest(alg, clientX509.getTBSCertificate());
      byte[] digest = md.digest();

      String prefix =null;
      if(cacheservice!=null){
        prefix=cacheservice.getCommonName(clientX509);
      }
      alias = prefix + "-" +CertificateUtility.toHex(digest);
    }
    catch (Exception e) {
      log.error("Unable to get alias: " + e);
    }
    return alias;
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
/*
  This function was part of directorykeystore but I could not find any reference in our code
  or in the core code


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

*/

  /* This function was part of directorykeystore but I could not find any reference in our code
     or in the core code

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
  */



  public void updateNS(String commonName) {

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

  public void updateNS(CertificateEntry certEntry) throws Exception {
    if (log.isDebugEnabled()) {
      log.debug("updateNS(CertEntry ) called: " + certEntry.toString());
    }
    namingService.updateCert(certEntry);

  }
  /**
   * Adding LDAP URL entry in the naming service.
   */
  public void updateNS(X500Name x500Name) {
    if (log.isDebugEnabled()) {
      log.debug("updateNS(X500Name) called: " + x500Name);
    }

// check whether cert exist and whether it is agent
    if(cacheservice==null) {
      log.warn("Unable to get Certificate cache Service in updateNS");
    }

    String title = CertificateUtility.findAttribute(x500Name.getName(), "t");
    if (title == null) {
      return;
    }
    if (!title.equals(CertificateCacheConstants.CERT_TITLE_AGENT)
	&& !title.equals(CertificateCacheConstants.CERT_TITLE_NODE)) {
      if (log.isDebugEnabled()) {
        log.debug("Not publishing " + x500Name + " to naming, because it is not an agent.");
      }
      return;
    }
    /*
    List certificateList = findCert(x500Name, KeyRingService.LOOKUP_KEYSTORE,true );
    if (certificateList == null || certificateList.size() == 0) {
      log.warn("Not registering LDAP URL to naming service. Cannot find certificate. DN:" + x500Name);
      return;
    }
    */
    // cannot publish a certificate that does not belong to local
    List pkeyList = getValidPrivateKeys(x500Name);
    if (pkeyList == null || pkeyList.size() == 0) {
      log.warn("Not registering " + x500Name + " to naming, cannot find private key.");
      return;
    }
    try {
      //CertificateStatus cs = (CertificateStatus)certificateList.get(0);
      CertificateStatus cs = ((PrivateKeyCert)pkeyList.get(0)).getCertificateStatus();
      CertificateEntry certEntry=null;
      /*
      if( cs.getCertificateType()==CertificateType.CERT_TYPE_CA) {
         log.warn("Received cert in UpdateNS is "+cs.getCertificate().getSubjectDN().getName());
        return;
      }

      else {
      */
        certEntry = new CertificateEntry(cs.getCertificate(),
                                         // of course the cert is trusted by local node, otherwise not valid
                                         CertificateRevocationStatus.VALID,
                                         cs.getCertificateType());
      //}
      certEntry.setCertificateChain(cs.getCertificateChain());
      namingService.updateCert(certEntry);

    } catch (Exception nx) {
      if (log.isWarnEnabled()) {
	log.warn("Cannot update "+x500Name+ " cert in naming." + nx.toString(), nx);
      }
    }

    //log.warn("Cannot update agent ldap in naming.");
  }


  public void publishCertificate(CertificateEntry certEntry) {

    boolean status=false;
    try {
      status= namingService.updateCert(certEntry);
    }
    catch (Exception exp) {
      if (log.isWarnEnabled()) {
	log.warn("Cannot update cert in naming." + certEntry.getCertificate().getSubjectDN().getName());
      }
    }
    if(status) {
      if (log.isDebugEnabled()) {
	log.debug("Sucessfully update cert in naming." + certEntry.getCertificate().getSubjectDN().getName());
      }
    }
    else {
      if (log.isWarnEnabled()) {
	log.warn("Update cert in naming FAILED ." + certEntry.getCertificate().getSubjectDN().getName());
      }
    }
  }

  public boolean checkExpiry(String commonName) {
    boolean expired = false;
    TrustedCaPolicy [] tc = cryptoClientPolicy.getIssuerPolicy();
    if (tc.length == 0) {
      // should not check expiry if haven't received trusted policy

      // root CA
      //expired = checkExpiry(commonName, null);
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
    // certificate have not been generated yet, still waiting in initial stage
    // after handleRequestedIdentities are called the table becomes irelevant
    if (_requestingIdentities) {
      return false;
    }

    CertificateAttributesPolicy certAttribPolicy =
      cryptoClientPolicy.getCertificateAttributesPolicy(trustedCaPolicy);
    String x500dn = CertificateUtility.getX500DN(commonName,
      CertificateCache.getTitle(commonName), certAttribPolicy);
    X500Name x500name = CertificateUtility.getX500Name(x500dn);

    // check local keystore only, cert may have been generated but just have not updated to WP yet
    List certificateList = findCert(x500name, KeyRingService.LOOKUP_KEYSTORE, true);

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
    else {
    // it claims certificates have been generated, is it true?
      certificateList = findCert(x500name, KeyRingService.LOOKUP_KEYSTORE, false);
      if (certificateList == null || certificateList.size() == 0) {
        if (log.isWarnEnabled()) {
          log.warn("Missing certificate for " + commonName + ", adding it to request monitor thread.");
        }

        // let the certificate request thread handle it
        CertValidityService validityService = (CertValidityService)
          serviceBroker.getService(this,
                                 CertValidityService.class,
                                 null);
        validityService.addCertRequest(x500name, false, trustedCaPolicy);
        serviceBroker.releaseService(this,
                                   CertValidityService.class,
                                   validityService);
        return false;
      }
    }

    // expired, regen key
    if (log.isDebugEnabled())
      log.debug("Certificate expired, requesting again.");

    // TODO: get the certificate that is expiring, get the trusted CA
    // from signer, then find the TrustedCaPolicy.
    addKeyPair(commonName,null, trustedCaPolicy);
    // Problem: If a certificate has been revoked, the CA should not regenerate a certificate
    // automatically. However, this is what the CA is doing right now.
    // In the checkExpiry method, we call findCert() first, which returns null if the certificate
    // has been revoked. The method would then re-issue a new certificate, and a new
    // valid certificate would be generated.
    // For now, the code is commented out as a workaround, but this should be fixed.

    return true;
  }


  public String getX500DN(String commonName) {
    String title=CertificateCache.getTitle(commonName);
    return CertificateUtility.getX500DN(commonName,title, cryptoClientPolicy.getCertificateAttributesPolicy());
  }


  public void setKeyEntry(PrivateKey key, X509Certificate cert) {

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

  public void removeEntry(String commonName)  {
    if (log.isInfoEnabled()) {
      log.info("Removing entry from keystore:" + commonName);
    }

    String alias = findAlias(commonName);

    if(cacheservice==null) {
      log.warn(" Unabale to get Certificate cache service in removeEntry");
    }
    if(cacheservice!=null){
      cacheservice.deleteEntry(alias, commonName);
    }
    if (log.isDebugEnabled()) {
      if(cacheservice!=null){
        cacheservice.printCertificateCache();
      }
    }

    // TODO: for node, hostname, CA aliases, need to get replacement
  }


  /** @param privKey        The private keys to store in a PKCS#12 enveloppe
   *  @param cert           The certificate to store in a PKCS#12 enveloppe
   *  @param signerPrivKey  The private key of the signer
   *  @param signerCert     The certificate of the signer
   *  @param rcvrCert       The certificate of the intended receiver
   */
  public byte[] protectPrivateKey(List privKey,
				  List cert,
				  PrivateKey signerPrivKey,
				  X509Certificate signerCert,
				  X509Certificate rcvrCert)
    {
      return pkcs12.protectPrivateKey(privKey,
				      cert,
				      signerPrivKey,
				      signerCert,
				      rcvrCert);
    }

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private keys of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  public PrivateKeyCert[] getPfx(byte[] pfxBytes,
				 List rcvrPrivKey,
				 List rcvrCert)
    {
      return pkcs12.getPfx(pfxBytes,
			   rcvrPrivKey,
			   rcvrCert);
    }

/*
  public X509CRL getCRL(String  distingushname) {

  X509CRL crl=null;
  crl=search.getCRL(distingushname);
  return crl;
  }

  public  CertDirectoryServiceClient getCACertDirServiceClient(String dname) {
  return directoryKeystore.getCACertDirServiceClient(dname);
  }

  public void checkOrMakeCert(X500Name dname, boolean isCACert, TrustedCaPolicy tc) {
  if (directoryKeystore == null) {
  return;
  }
  directoryKeystore.checkOrMakeCert(dname, isCACert, tc);
  return;
  }
*/

  public void searchCert(X500Name x500Name)
    {
      if (log.isDebugEnabled()) {
	log.debug("searchCert called :" + x500Name);
      }
      List certs = search.findCert(x500Name);
      if (certs == null || certs.size() == 0) {
        if (log.isInfoEnabled()) {
          log.info("Failed to lookup certificate for " + x500Name);
        }
      }
      CRLCacheService crlCacheservice=(CRLCacheService)
        AccessController.doPrivileged(new PrivilegedAction() {
          public Object run() {
            return serviceBroker.getService(this, CRLCacheService.class, null);
          }
        });
      for (int i = 0 ; i < certs.size() ; i++) {
	// Since the certificate comes from an LDAP server, it should be trusted
	// (because only a CA should publish certificates to the directory service,
	// but let's check just to make sure. There may be some cases where
	// a particular CA is not trusted locally.
        CertificateEntry entry = (CertificateEntry)certs.get(i);
        CertificateStatus certstatus = null;
	try {
	  // Richard: need to check whether the certificate already exist in
	  // cache. This happens with multiple CAs. When CRL is updated with
	  // status, next time findCert will lookup the revoked CA cert (cannot
	  // find any valid cert from cache) from LDAP and update it in the
	  // cache as trusted
          X509Certificate certificate = entry.getCertificate();
	  //X500Name x500Name = nameMapping.getX500Name(certificate.getSubjectDN().getName());
	  //X500Name x500Name = CertificateUtility.getX500Name(certificate.getSubjectDN().getName());

	  //if (x500Name != null) {

	  X509Certificate [] certChain = checkCertificateTrust(certificate);
          entry.setCertificateChain(certChain);

	  if(entry.getCertificateTrust().equals(CertificateTrust.CERT_TRUST_REVOKED_CERT)) {
            // now can truly set certificate validity
	    certstatus = new CertificateStatus(certificate,
					       CertificateOrigin.CERT_ORI_LDAP,
					       CertificateRevocationStatus.REVOKED,
					       entry.getCertificateType(),
					       CertificateTrust.CERT_TRUST_REVOKED_CERT,
					       null);
	    // certstatus.setValidity(false);
	  }
	  else {
	    certstatus = new CertificateStatus(certificate,
					       CertificateOrigin.CERT_ORI_LDAP,
					       CertificateRevocationStatus.VALID,
					       entry.getCertificateType(),
					       CertificateTrust.CERT_TRUST_CA_SIGNED,
					       null);
	  }
          certstatus.setCertificateChain(entry.getCertificateChain());

	  if (log.isDebugEnabled()) {
	    log.debug("Updating cert cache with entry:" + x500Name);
	  }
	  if(cacheservice!=null) {
	    cacheservice.addCertificate(certstatus);
	    // Update Common Name to DN hashtable
	    cacheservice.addNameToNameMapping(certstatus);
	  }

	  if(certstatus.getCertificateType().equals(CertificateType.CERT_TYPE_CA)) {
	    if (log.isDebugEnabled()) {
	      log.debug("Certificate type is CA certificate");
	      log.debug("Updating CRLCache  with CA entry ");
	    }

	    if(crlCacheservice!=null) {
              crlCacheservice.addToCRLCache(certificate.getSubjectDN().getName());
	    }
	    else {
	      log.warn(" Uable to add CA to CRL Cache as CRL Cache service is null" +
		       certificate.getSubjectDN().getName());
	    }
	  }
	}
	catch (CertificateChainException e) {
          // there is a flow of warnings from this if certificate is not updated
          // to cache yet
          if (System.getProperty("org.cougaar.core.autoconfig", "false").equals("true")) {
            if (log.isDebugEnabled()) {
              log.debug("Found non trusted cert in cert directory! "
                        + x500Name + " - " + e);
            }
          }
          else {
            if (log.isWarnEnabled()) {
              log.warn("Found non trusted cert in cert directory! "
                       + x500Name + " - " + e);
            }
          }
	}
	catch (CertificateExpiredException e) {
	  // The certificate is trusted but it has expired.
	  if (log.isWarnEnabled()) {
	    log.warn("Certificate in chain has expired. "
		     + x500Name + " - " + e);
	  }
	}
	catch (CertificateNotYetValidException e) {
	  // The certificate is trusted but it is not yet valid. Add it to the cache
	  // because it may become valid when it is being used.
	  if (log.isWarnEnabled()) {
	    log.warn("Certificate in chain is not yet valid. "
		     + x500Name + " - " + e);
	  }
	  certstatus = new CertificateStatus(entry.getCertificate(),
					     CertificateOrigin.CERT_ORI_LDAP,
					     CertificateRevocationStatus.VALID,
					     entry.getCertificateType(),
					     CertificateTrust.CERT_TRUST_CA_SIGNED,
					     null);
          certstatus.setCertificateChain(entry.getCertificateChain());
	  if (log.isDebugEnabled()) {
	    log.debug("Updating cert cache with cert entry:" + x500Name);
	  }
	  if(cacheservice!=null) {
	    cacheservice.addCertificate(certstatus);
	    // Update Common Name to DN hashtable
	    cacheservice.addNameToNameMapping(certstatus);
	  }
	}
	catch (CertificateRevokedException certrevoked) {
	  if (log.isInfoEnabled()) {
	    log.info("Found cert in cert directory which has been revoked ! "
		      + x500Name + " - " + certrevoked);
	  }
	}
      }
      serviceBroker.releaseService(this,
                                   CRLCacheService.class,
                                   crlCacheservice);
    }

  public List getX500NameFromNameMapping(String name) {
    if(cacheservice==null) {
      log.warn(" Unable to get Certificate Cache service in findPrivateKey");
      return null;
    }
    return cacheservice.getX500NameFromNameMapping(name);
  }

  public void addToIgnoredList(String cname) throws Exception {
    // for agent it must be already exist, otherwise this will introduce a security hole
    if (cname.equals(NodeInfo.getNodeName())) {
      ignoredList.add(cname);
      return;
    }

    List l = findCert(cname, KeyRingService.LOOKUP_KEYSTORE);
    if (l != null && l.size() != 0) {
      ignoredList.add(cname);
      return;
    }

    throw new GeneralSecurityException("Requesting to ignore unrecognized agent " + cname);
  }

  public X509KeyManager getClientSSLKeyManager()
    throws IllegalStateException
  {
    KeyManager clientSSLkm = null;
    for (Iterator kmIt = _initKeyManager.iterator(); kmIt.hasNext();) {
      KeyManager km = (KeyManager) kmIt.next();
      if (km instanceof UserKeyManager || km instanceof ServerKeyManager) {
        continue;
      } else if (clientSSLkm == null) {
        clientSSLkm = km;
      } else {
        throw new IllegalStateException("More than one possibility for " +
                                        "the ssl client key manager");
      }
    }
    return clientSSLkm;
  }

  public boolean isManagerReady() {
  	return ServerKeyManager.isManagerReady();
  }
  
  /**
   * DOCUMENT ME!
   *
   * @param commonName DOCUMENT ME!
   * @param keyAlias DOCUMENT ME!
   * @param trustedCaPolicy DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */

  protected synchronized PrivateKey addKeyPair(String commonName,
      String keyAlias, TrustedCaPolicy trustedCaPolicy) {
      CertificateAttributesPolicy certAttribPolicy = cryptoClientPolicy
        .getCertificateAttributesPolicy(trustedCaPolicy);
      X500Name dname = CertificateUtility.getX500Name(CertificateUtility
          .getX500DN(commonName, CertificateCache.getTitle(commonName),
            certAttribPolicy));
      return certRequestor.addKeyPair(dname, keyAlias, false, trustedCaPolicy);
    }

  /**
   * DOCUMENT ME!
   *
   * @param alias DOCUMENT ME!
   * @param certificateChain DOCUMENT ME!
   *
   * @throws CertificateException DOCUMENT ME!
   * @throws KeyStoreException DOCUMENT ME!
   * @throws NoSuchAlgorithmException DOCUMENT ME!
   * @throws UnrecoverableKeyException DOCUMENT ME!
   */
  public void installCertificate(String alias,
    X509Certificate[] certificateChain)
    throws CertificateException, KeyStoreException, NoSuchAlgorithmException, 
      UnrecoverableKeyException {
    X509Certificate[] certificateForImport;

    X509Certificate certificate = null;
    PrivateKey privatekey = null;
    if (cacheservice != null) {
      certificate = cacheservice.getCertificate(alias);
      privatekey = cacheservice.getKey(alias);
    }

    if (certificate == null) {
      log.error(alias
        + " has no certificate. Cannot install certificate signed by CA.");
      throw new CertificateException(alias + " has no certificate");
    }

    if (privatekey == null) {
      log.error(alias
        + " has no Private key . Cannot install certificate signed by CA.");
      throw new CertificateException(alias + " has no Private Key ");
    }

    if (certificateChain.length == 1) {
      // There is no certificate chain.
      // We have to construct the chain first.
      if (log.isDebugEnabled()) {
        log.debug("Certificate for alias :" + alias + "does not contain chain");
      }

      certificateForImport = establishCertChain(certificate, certificateChain[0]);
      if (log.isDebugEnabled()) {
        if (certificateForImport == null) {
          log.debug("certificate for import is null:");
        }

        log.debug(" successfullly established chain");
      }
    } else {
      // The PKCS7 reply contains the certificate chain.
      // Validate the chain before proceeding.
      certificateForImport = validateReply(alias, certificate, certificateChain);
    }

    if (certificateForImport != null) {
      if (cacheservice != null) {
        cacheservice.setKeyEntry(alias, privatekey, certificateForImport);
        log.debug(" adding certificate to certificate cache:" + alias);
        // The reply contains a certificate chain and it is valid
        cacheservice.addCertificateToCache(alias, certificateForImport[0],
          privatekey);
      }
    }
  }


  /** */
  public X509Certificate[] validateReply(String alias,
    X509Certificate certificate, X509Certificate[] certificateReply)
    throws CertificateException {
    java.security.PublicKey publickey = certificate.getPublicKey();
    int i;

    for (i = 0; i < certificateReply.length; i++) {
      if (publickey.equals(certificateReply[i].getPublicKey())) {
        break;
      }
    }

    if (i == certificateReply.length) {
      String s = "Certificate reply does not contain public key for <" + alias
        + ">";
      log.warn(s);
      throw new CertificateException(s);
    }

    X509Certificate certificate1 = certificateReply[0];
    certificateReply[0] = certificateReply[i];
    certificateReply[i] = certificate1;
    Principal principal = certificateReply[0].getIssuerDN();
    for (int j = 1; j < (certificateReply.length - 1); j++) {
      int l;
      for (l = j; l < certificateReply.length; l++) {
        Principal principal1 = certificateReply[l].getSubjectDN();
        if (!principal1.equals(principal)) {
          continue;
        }

        X509Certificate certificate2 = certificateReply[j];
        certificateReply[j] = certificateReply[l];
        certificateReply[l] = certificate2;
        principal = certificateReply[j].getIssuerDN();
        break;
      }

      if (l == certificateReply.length) {
        log.warn("Incomplete certificate chain in reply for " + alias);
        throw new CertificateException("Incomplete certificate chain in reply");
      }
    }

    for (int k = 0; k < (certificateReply.length - 1); k++) {
      java.security.PublicKey publickey1 = certificateReply[k + 1].getPublicKey();
      try {
        certificateReply[k].verify(publickey1);
      } catch (Exception exception) {
        log.warn("Certificate chain in reply does not verify: "
          + exception.getMessage());
        throw new CertificateException(
          "Certificate chain in reply does not verify: "
          + exception.getMessage());
      }
    }

    return certificateReply;
  }

  /**
   * DOCUMENT ME!
   *
   * @param certificate Contains the self-signed certificate
   * @param certificateReply Contains the certificate signed by the CA
   *
   * @return DOCUMENT ME!
   *
   * @throws CertificateException DOCUMENT ME!
   * @throws KeyStoreException DOCUMENT ME!
   */
  public X509Certificate[] establishCertChain(X509Certificate certificate,
    X509Certificate certificateReply)
    throws CertificateException, KeyStoreException {
    if (certificate == null) {
      log.error("establishCertChain: null certificate");
    }

    if (certificateReply == null) {
      log.error("establishCertChain: null certificate reply");
    }

    if (certificate != null) {
      java.security.PublicKey publickey = certificate.getPublicKey();
      java.security.PublicKey publickey1 = certificateReply.getPublicKey();
      if (!publickey.equals(publickey1)) {
        String s = "Public keys in reply and keystore don't match";
        log.warn(s);
        throw new CertificateException(s);
      }

      if (certificateReply.equals(certificate)) {
        String s1 = "Certificate reply and certificate in keystore are identical";
        log.debug(s1);
        throw new CertificateException(s1);
      }
    }

    return checkCertificateTrust(certificateReply);
  }

  /**
   * DOCUMENT ME!
   *
   * @param name DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */
  public String getNextAlias(String name) {
    String alias = name.toLowerCase() + "-";
    int nextIndex = 1;
    int ind;

    try {
      Enumeration list = null;
      if (cacheservice != null) {
        list = cacheservice.getAliasList();
      }

      while (list.hasMoreElements()) {
        //build up the hashMap
        String a = (String) list.nextElement();
        if (a.startsWith(alias)) {
          //Extract index
          try {
            ind = Integer.valueOf(a.substring(alias.length())).intValue();
          } catch (NumberFormatException e) {
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
    } catch (Exception e) {
      log.error("Unable to get next alias:" + e.toString());
    }

    alias = alias + nextIndex;
    if (log.isDebugEnabled()) {
      log.debug("Next alias for " + name + " is " + alias);
    }

    return alias;
  }




  
}

