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
import java.math.BigInteger;
import java.security.cert.*;
import java.security.KeyStore;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.InvalidKeyException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import sun.security.x509.*;
import sun.security.util.DerValue;
import sun.security.util.DerInputStream;
import sun.security.util.ObjectIdentifier;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.lang.reflect.*;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.Component;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.BindingSite;
import org.cougaar.util.ConfigFinder;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.SchedulerService;
import org.cougaar.core.service.AlarmService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.BlackboardQueryService;
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.blackboard.BlackboardClientComponent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.service.AlarmService;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.Trigger;
import org.cougaar.util.TriggerModel;
import org.cougaar.util.SyncTriggerModelImpl;
import org.cougaar.core.blackboard.SubscriptionWatcher;

import org.cougaar.core.mts.MessageAddress;

// Cougaar security services
import org.cougaar.core.security.crlextension.x509.extensions.*;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.crypto.*;
import  org.cougaar.core.security.crypto.crl.blackboard.*;
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.util.*;

final public class CRLCache implements Runnable,CRLCacheService,BlackboardClient {

  private SecurityPropertiesService secprop = null;
  private DirectoryKeyStoreParameters param;
  private KeyStore caKeystore = null; 
  private Hashtable crlsCache = new Hashtable(50);
  private long sleep_time=60000l; // Check CRL every minute by default

  private ServiceBroker serviceBroker;
  private LoggingService log;
  private ConfigParserService configParser = null; 
  private NodeConfiguration nodeConfiguration;
  private boolean bbservicefirsttime=false;
  
  protected String blackboardClientName;
  protected AlarmService alarmService;
  
/** How long do we wait before retrying to send a certificate signing
 * request to a certificate authority? */
  private long crlrefresh = 10;
  private BlackboardService blackboardService=null;
  private CrlManagementService crlMgmtService=null;
  private IncrementalSubscription crlresponse;
  private BindingSite bindingSite=null;
  private CrlCacheBlackboardComponent crlBlackboardComponent=null;

  public CRLCache(ServiceBroker sb,BindingSite bs ){
    serviceBroker = sb;
    bindingSite=bs;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class, null);
    //this.keystore=dkeystore;
    if(log.isDebugEnabled()) {
      log.debug("Crl cache being initialized  ++++++++++");
    }
    long poll = 0;
    try {
      poll = (Long.valueOf(secprop.getProperty(secprop.CRL_POLLING_PERIOD))).longValue() * 1000;
    }
    catch (Exception e) {}
    if (poll != 0) {
      setSleepTime(poll);
    }
    configParser = (ConfigParserService)
      serviceBroker.getService(this,
			       ConfigParserService.class,
			       null);
    if (secprop == null) {
      throw new RuntimeException("unable to get security properties service");
    }
    if (configParser == null) {
      throw new RuntimeException("unable to get config parser service");
    }
    SecurityPolicy[] sp =
      configParser.getSecurityPolicies(CryptoClientPolicy.class);
    
    CryptoClientPolicy cryptoClientPolicy = (CryptoClientPolicy) sp[0];
    
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
    //param = new DirectoryKeyStoreParameters();
    String nodeDomain = cryptoClientPolicy.getCertificateAttributesPolicy().domain;
    nodeConfiguration = new NodeConfiguration(nodeDomain, serviceBroker);
    //param.keystorePath = nodeConfiguration.getNodeDirectory()
    // + cryptoClientPolicy.getKeystoreName();
    //param.isCertAuth = configParser.isCertificateAuthority();

    // ldap info and isCertAuth are moved out of param
    // no need to load from trust store, CertificateCache is already doing that
    /*
    TrustedCaPolicy[] trustedCaPolicy = cryptoClientPolicy.getTrustedCaPolicy();
    if (trustedCaPolicy.length > 0) {
      param.ldapServerUrl = trustedCaPolicy[0].certDirectoryUrl;
      param.ldapServerType = trustedCaPolicy[0].certDirectoryType;
      log.warn("trustedCaPolicy:" +	param.ldapServerUrl + 	param.ldapServerType);
    }
    if(param.isCertAuth) {
      X500Name [] caDNs=configParser.getCaDNs();
      if (caDNs.length > 0) {
	String caDN=caDNs[0].getName();
	CaPolicy capolicy=configParser.getCaPolicy(caDN);
	param.ldapServerUrl =capolicy.ldapURL;
	param.ldapServerType =capolicy.ldapType;
	param.defaultCaDn = caDN;
      }
    }
    log.warn("trustedCaPolicy:" +	param.ldapServerUrl + 	param.ldapServerType); 
    if(! param.isCertAuth) {
      // CA keystore parameters
      ConfigFinder configFinder = ConfigFinder.getInstance();
      param.caKeystorePath = nodeConfiguration.getNodeDirectory()
	+ cryptoClientPolicy.getTrustedCaKeystoreName();
      param.caKeystorePassword =
	cryptoClientPolicy.getTrustedCaKeystorePassword().toCharArray();
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
	File cafile2 = configFinder.locateFile(cryptoClientPolicy.getTrustedCaKeystoreName());
	if (cafile2 != null) {
	  param.caKeystorePath = cafile2.getPath();
	}
	else {
	  if (param.isCertAuth) {
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
	  else {
	    log.error("CA keystore (" + param.caKeystorePath +
		      ") unavailable. At least one CA certificate should be included");
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
      try {
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
      
      }
      catch (Exception e) {
	log.error("Unable to initialize Certificate Cache : ", e);
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
      initCRLCache();
    }
	*/
      	
    blackboardService = (BlackboardService) serviceBroker.getService(	this,
									BlackboardService.class,
									null);
    if(blackboardService==null) {
      log.debug(" adding service listner for blackboard service :");
      serviceBroker.addServiceListener(new BlackboardServiceAvailableListener());
    }
          
    crlMgmtService=(CrlManagementService)serviceBroker.getService(this, 
								  CrlManagementService.class, 
								  null);
    if(crlMgmtService==null) {
      log.debug(" adding service listner for CRL Management  service :");
      serviceBroker.addServiceListener(new CrlManagementServiceAvailableListener());
    }
    
  }
  
  public void startThread() {
    Thread td=new Thread(this,"crlthread");
    td.setPriority(Thread.NORM_PRIORITY);
    td.start();
  }

  public void addToCRLCache(String dnname,String ldapURL,int ldapType){	
    log.debug("addToCRLCache  -  "+ dnname + ldapURL +ldapType);
    CRLWrapper wrapper=null;
    if(!entryExists(dnname)) {
      wrapper=new CRLWrapper(dnname,ldapURL,ldapType);//,certcache);
      crlsCache.put(dnname,wrapper);
      if((blackboardService!=null) && (crlMgmtService!=null )){
	blackboardService.openTransaction();
	CRLAgentRegistration crlagentregistartion=new CRLAgentRegistration (dnname,ldapURL,ldapType);
	  
	/*Please Note ClusterIdentifier has been hard coded . Mechanism needs to be worked out 
	  so that in actual deployment it will be an ABA which targets set of agents that are 
	  running to provide CRL updates .
	     
	*/
	  
	CrlRelay crlregrelay=crlMgmtService.newCrlRelay(crlagentregistartion,
							MessageAddress.getMessageAddress("SocietySecurityManager"));
	log.debug(" CRL rely is being published :"+ crlregrelay.toString());
	blackboardService.publishAdd(crlregrelay);
	blackboardService.closeTransaction();
	  
      }
    }
    else {
      if(log.isDebugEnabled()) {
	log.debug("Warning !!! Entry already exists for dnname :" +dnname);
      }
    }
  }

  public void setSleepTime(long sleeptime) {
    sleep_time=sleeptime;
    if (log.isDebugEnabled()) {
      log.debug("CRL polling interval set to " + (sleep_time / 1000) + "s");
    }
  }

  public long getSleepTime() {
    return sleep_time;
  }

  private boolean entryExists(String dnname){
    return crlsCache.containsKey(dnname);
  }

  /** Lookup Certificate Revocation Lists */
  public void run() {
    Thread td=Thread.currentThread();
    td.setPriority(Thread.MIN_PRIORITY);
    while(true) {
      if(log.isDebugEnabled())
	log.debug("CRL CACHE THREAD IS RUNNING +++++++++++++++++++++++++++++++++++++++++");
      try {
	Thread.sleep(sleep_time);
      }
      catch(InterruptedException interruptedexp) {
	interruptedexp.printStackTrace();
      }
      String dnname=null;
      Enumeration enumkeys =crlsCache.keys();
      for(;enumkeys.hasMoreElements();) {
	dnname=(String)enumkeys.nextElement();
	updateCRLCache(dnname);
      }
      enumkeys=crlsCache.keys();
      for(;enumkeys.hasMoreElements();) {
	dnname=(String)enumkeys.nextElement();
	if(dnname!=null) {
	  updateCRLInCertCache(dnname);
	}
	else {
	  if(log.isWarnEnabled()) {
	    log.warn("Dn name is null in thread of crl cache :");
	  }
	}
      }
    }
  }

  /**
   */
  private void updateCRLInCertCache(String distingushName) {
    X509CRL crl=null;
    CRLWrapper wrapper=null;
    wrapper=(CRLWrapper) crlsCache.get(distingushName);
    crl=wrapper.getCRL();
    if(crl==null) {
      return;
    }
    Set crlset=crl.getRevokedCertificates();
    Iterator iter=null;
    if((crlset==null)||(crlset.isEmpty())){
      return;
    }
    iter=crlset.iterator();
    X509CRLEntry crlentry=null;
    for(;iter.hasNext();) {
      crlentry=(X509CRLEntry)iter.next();
      updateCRLEntryInCertCache(crlentry,distingushName);
    }

  }

  
  public void updateCRLCache(CRLWrapper wrapperFromDirectory) {

    String distingushname=wrapperFromDirectory.getDN();
    log.debug("Update CRLCache is called from CRLCache BlackBoard Component :");
    if(log.isDebugEnabled()) {
      log.debug(" Updating crl cache for :"+distingushname);
    }
    X509CRL crl=null;
    CRLWrapper wrapper=null;
    PublicKey crlIssuerPublickey =null;
    X509Certificate crlIssuerCert=null;
    X500Name name =null;
    crl=wrapperFromDirectory.getCRL();
    try {
      name =  new X500Name(distingushname);
    }
    catch(Exception exp) {
      log.error("Unable to get CA name: " + distingushname);
    }
    CertificateCacheService cacheservice=(CertificateCacheService)
      serviceBroker.getService(this,
			       CertificateCacheService.class,
			       null);
    KeyRingService keyRingService=(KeyRingService)
      serviceBroker.getService(this,
			       KeyRingService.class,
			       null);

    if(keyRingService==null) {
      log.warn("Unable to get  Ring Service in updateCRLCache");
      return;
    }
    List certList = keyRingService.getValidCertificates(name);
    CertificateStatus certstatus = null;
    if (certList != null && certList.size() != 0) {
      // For now, get the first certificate
      certstatus = (CertificateStatus) certList.get(0);
    }
    else {
      if(log.isWarnEnabled())
	log.warn("No valid certificate for: "+distingushname);
      return;
    }
    crlIssuerCert=(X509Certificate)certstatus.getCertificate();
    crlIssuerPublickey=crlIssuerCert.getPublicKey();
    try {
      crl.verify(crlIssuerPublickey);
    }
    catch (NoSuchAlgorithmException  noSuchAlgorithmException) {
      noSuchAlgorithmException.printStackTrace();
      return ;
    }
    catch (InvalidKeyException invalidKeyException ) {
      invalidKeyException.printStackTrace();
      return ;
    }
    catch (NoSuchProviderException noSuchProviderException ){
      noSuchProviderException.printStackTrace();
      return ;
    }
    catch (SignatureException  signatureException ) {
      signatureException.printStackTrace();
      return ;
    }
    catch (CRLException cRLException ) {
      cRLException.printStackTrace();
      return ;
    }
    try {
      if(keyRingService!=null) {
	keyRingService.checkCertificateTrust(crlIssuerCert);
      }
      else {
	log.warn("Unable to check certificate trust as keyring service is null");
      }
    }
    catch(Exception exp) {
      exp.printStackTrace();
      return;
    }
    if(crl!=null) {
      wrapper=(CRLWrapper) crlsCache.get(distingushname);
      try {
	wrapper.setCRL(crl.getEncoded());
      }
      catch(Exception exp) {
	log.warn("Unable to set crl in cache for :"+distingushname +exp.getMessage());
      }
      wrapper.setLastModifiedTimestamp(wrapperFromDirectory.getLastModifiedTimestamp());
      crlsCache.put(distingushname,wrapper);
      updateCRLInCertCache(distingushname);
    }
    
  }

  /**
   */
  private void updateCRLCache(String distingushname) {
    if(log.isDebugEnabled()) {
      log.debug(" Updating crl cache for :"+distingushname);
    }
    X509CRL crl=null;
    CRLWrapper wrapper=null;
    PublicKey crlIssuerPublickey =null;
    X509Certificate crlIssuerCert=null;
    X500Name name =null;
    try {
      name =  new X500Name(distingushname);
    }
    catch(Exception exp) {
      log.error("Unable to get CA name: " + distingushname);
    }
    CertificateCacheService cacheservice=(CertificateCacheService)
      serviceBroker.getService(this,
			       CertificateCacheService.class,
			       null);
    KeyRingService keyRingService=(KeyRingService)
      serviceBroker.getService(this,
			       KeyRingService.class,
			       null);

    if(keyRingService==null) {
      log.warn("Unable to get  Ring Service in updateCRLCache");
      return;
    }
    List certList = keyRingService.getValidCertificates(name);
    CertificateStatus certstatus = null;
    if (certList != null && certList.size() != 0) {
      // For now, get the first certificate
      certstatus = (CertificateStatus) certList.get(0);
    }
    else {
      if(log.isWarnEnabled())
	log.warn("No valid certificate for: "+distingushname);
      return;
    }

/*    
    // check whether it is specified in the policy
    CertDirectoryServiceClient certificateFinder =null;
    if(keyRingService!=null) {
      certificateFinder=keyRingService.getCACertDirServiceClient(distingushname);
    }
    
    // check whether it is found in trust chain
    if (certificateFinder == null) {
      certificateFinder = certstatus.getCertFinder();
      if (log.isDebugEnabled())
        log.debug("Get cert finder from status: " + certificateFinder);
    }
    // pretty much not found, check it is in the naming service
*/
    
    crlIssuerCert=(X509Certificate)certstatus.getCertificate();
    crlIssuerPublickey=crlIssuerCert.getPublicKey();
/*
    if(certificateFinder== null) {
      if(log.isWarnEnabled())
	log.warn("No certificateFinder present in Directory keystore in update CRL :"+distingushname);
    }
*/
    try {
      //crl=keyRingService.getCRL(distingushname);
      crl = null;
    }
    catch (Exception e) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to get CRL for " + distingushname + ". Will retry later");
      }
      return;
    }
    if(crl==null) {
      if(log.isInfoEnabled()) {
	log.info("No crl present for:"+distingushname + ". Will retry later");
      }
      return;
    }
    try {
      crl.verify(crlIssuerPublickey);
    }
    catch (NoSuchAlgorithmException  noSuchAlgorithmException) {
      noSuchAlgorithmException.printStackTrace();
      return ;
    }
    catch (InvalidKeyException invalidKeyException ) {
      invalidKeyException.printStackTrace();
      return ;
    }
    catch (NoSuchProviderException noSuchProviderException ){
      noSuchProviderException.printStackTrace();
      return ;
    }
    catch (SignatureException  signatureException ) {
      signatureException.printStackTrace();
      return ;
    }
    catch (CRLException cRLException ) {
      cRLException.printStackTrace();
      return ;
    }
    try {
      if(keyRingService!=null) {
	keyRingService.checkCertificateTrust(crlIssuerCert);
      }
      else {
	log.warn("Unable to check certificate trust as keyring service is null");
      }
    }
    catch(Exception exp) {
      exp.printStackTrace();
      return;
    }
    if(crl!=null) {
      wrapper=(CRLWrapper) crlsCache.get(distingushname);
      try {
	wrapper.setCRL(crl.getEncoded());
      }
      catch(Exception exp) {
	log.warn("Unable to encode crl in CRL cache :"+ distingushname + " message :"+exp.getMessage());
      }
      crlsCache.put(distingushname,wrapper);
    }

  }

  private void updateCRLEntryInCertCache(X509CRLEntry crlentry,String Issuerdn)  {
    if(log.isDebugEnabled()) {
      log.debug("crl enty in updateCRLEntryInCertCache is :"+crlentry.toString());
    }
    BigInteger bigint=crlentry.getSerialNumber();
    boolean hasextensions=crlentry.hasExtensions();
    String actualIssuerDN=null;
    String subjectDN=null;
    Set oidset=null;
    String oid=null;
    byte[] issuerbytes=null;
    CRLKey crlkey=null;
    if(hasextensions) {
      oidset= crlentry.getNonCriticalExtensionOIDs();
      if(!oidset.isEmpty()) {
	Iterator iter=oidset.iterator();
	if(iter.hasNext()) {
	  oid=(String)iter.next();
	  if(log.isDebugEnabled())
	    log.debug(" Got oid for non critical extension in updateCRLEntryInCertCache is :"+oid);
	}
	if(oid!=null) {
	  issuerbytes=crlentry.getExtensionValue(oid);
	  
	  if(issuerbytes==null) {
	    log.debug(" Got issuerbytes as null for oid :" +oid );
	  }
	  try{
	    if(log.isDebugEnabled())
	      log.debug(" going to get extension class in CRL Caches updateCRLEntryInCertCache :");
	    Class class1 = OIDMap.getClass(new ObjectIdentifier(oid));
	    if(class1 == null) {
	      if(log.isDebugEnabled())
		log.debug(" Class was null in CRL Caches updateCRLEntryInCertCache :");
	      return;
	    }
	    Class aclass[] = {
	      java.lang.Boolean.class, java.lang.Object.class
	    };
	    Constructor constructor = class1.getConstructor(aclass);
	    DerInputStream dis=new DerInputStream(issuerbytes);
	    DerValue val=dis.getDerValue();
	    byte[] byted=val.getOctetString();
	    byte abyte0[] =byted;
	    int i = abyte0.length;
	    Object obj = Array.newInstance(Byte.TYPE, i);
	    for(int j = 0; j < i; j++){
	      Array.setByte(obj, j, abyte0[j]);
	    }
	    Object aobj[] = { new Boolean(false), obj };
	    CertificateIssuerExtension ciext=new CertificateIssuerExtension( new Boolean(false),obj);
	    CertAttrSet certattrset = (CertAttrSet)constructor.newInstance(aobj);
	    if(certattrset instanceof CertificateIssuerExtension) {
	      CougaarGeneralNames gn=(CougaarGeneralNames) certattrset.get
		(CertificateIssuerExtension.ISSUERNAME);
	      if(log.isDebugEnabled())
		log.debug(" gneral names are in CRL Caches updateCRLEntryInCertCache  :"+gn.toString());
	      if(gn.size()==1){
		GeneralName  name=(GeneralName)gn.elementAt(0);
		if(name.getType()==4)  {
		  if(log.isDebugEnabled())
		    log.debug("got actual data from extension in  CRL Caches updateCRLEntryInCertCache :"+name.toString());
		  actualIssuerDN=name.toString();
		}
		else
		  log.debug("Error !!!! not x500 name ");
	      }
	    }
	    else {
	      log.debug("Warning !!!!!!  not instance of CertificateIssuerExtension");
	    }
	  }
	  catch(InvocationTargetException invocationtargetexception)  {
	    //throw new CRLException(invocationtargetexception.getTargetException().getMessage());
	    invocationtargetexception.printStackTrace();
	  }
	  catch(Exception exception)  {
	    //throw new CRLException(exception.toString());
	    exception.printStackTrace();
	  }

	}
      }
      else {
	if(log.isDebugEnabled())
	  log.debug("Error in getting extensions for crlentry :"+crlentry.toString());
      }

    }
    else {
      actualIssuerDN=Issuerdn;
    }

    crlkey=new CRLKey(bigint,actualIssuerDN);
    if(log.isDebugEnabled()) {
      log.debug("Going to look for key  in CRL Caches updateCRLEntryInCertCache  :"+crlkey.toString());
      log.debug(" cache contains  in CRL Caches updateCRLEntryInCertCache:");

      //keystore.certCache.printbigIntCache();
    }
    CertificateCacheService cacheservice=(CertificateCacheService)
      serviceBroker.getService(this,
			       CertificateCacheService.class,
			       null);
    
    if(cacheservice==null) {
      log.warn("Unable to get Certificate cache Service in updateCRLEntryInCertCache");
    }
    subjectDN=null;
    if(cacheservice!=null) {
      subjectDN=cacheservice.getDN(crlkey);
      // need to store the revoked cert information even though
      // we may not have received the cert yet. Otherwise there
      // is a time window for a revoked cert to get into the 
      // system.  
      cacheservice.addToRevokedCache(actualIssuerDN, bigint);
    }
    if(subjectDN==null) {
      return;
    }
    if(log.isDebugEnabled()) {
      log.debug(" Got the dn for the revoked cert in CRL Caches updateCRLEntryInCertCache :"+subjectDN);
    }
    if(cacheservice!=null) {
      cacheservice.revokeStatus(bigint,actualIssuerDN,subjectDN);
    }
    else {
      log.warn("Unable to revoke status in certificate Cache as  Certificate cache Service is null");
    }

  }

  public void setSleeptime(long sleeptime){
    // Check security permissions
    SecurityManager security = System.getSecurityManager();
    if (security != null) {
      security.checkPermission(new KeyRingPermission("writeCrlparam"));
    }
    sleep_time=sleeptime;
  }

  public long getSleeptime(){
    return sleep_time;
  }
  
  public CRLWrapper getCRL(String dnname){
    return null;
  }

  public boolean isCertificateInCRL(X509Certificate subjectCertificate, String IssuerDN){
    boolean incrl=false;
    CRLWrapper crlwrapper=null;
    X509CRL crl=null;
    if(entryExists(IssuerDN)) {
      crlwrapper=(CRLWrapper)crlsCache.get(IssuerDN);
      crl=crlwrapper.getCRL();
      
    }
    return incrl;
  }
  
  private void initCRLCache(){
    try {
      //if(caKeystore != null && caKeystore.size() > 0) {
	if (log.isDebugEnabled()) {
	  log.debug("++++++ Initializing CRL Cache");
	}
	// Build a hash table that indexes keys in the CA keystore by DN
	//initCRLCacheFromKeystore(caKeystore, param.caKeystorePassword);
        initCRLCacheFromKeystore();
	this.startThread();
	/*
      }
      else {
	log.debug(" Initializing CRL Cache  caKeystore == null ||  caKeystore.size() > 0");
      }
	*/
    }
    catch (KeyStoreException e) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to access CA keystore: " + e);
      }
    }
  }
  
//  private void initCRLCacheFromKeystore(KeyStore aKeystore, char[] password)
  private void initCRLCacheFromKeystore()
    throws KeyStoreException {
    String s=null;
    X509Certificate certificate=null;
    String dnname=null;
    log.debug("initCRLCacheFromKeystore called :");
    KeyRingService keyRingService=(KeyRingService)
      serviceBroker.getService(this,
			       KeyRingService.class,
			       null);

    if(keyRingService==null) {
      log.error("Unable to get  Key Ring Service in initCRLCacheFromKeystore CRL cache willl register for KeyRing Service  ");
      return;
    }
    CertificateCacheService cacheService=(CertificateCacheService)
      serviceBroker.getService(this,
                               CertificateCacheService.class,
                               null);
	/*
    for(Enumeration enumeration = aKeystore.aliases(); enumeration.hasMoreElements(); ) {
      s = (String)enumeration.nextElement();
      certificate =(X509Certificate) aKeystore.getCertificate(s);
	*/
    X509Certificate trustedcerts[] = cacheService.getTrustedIssuers();
    for (int i = 0; i < trustedcerts.length; i++) {
      certificate = trustedcerts[i];
      dnname=certificate.getSubjectDN().getName();
      /*
        This information is no longer required it is job of the search impl to figure out where to obtain certificate info from

      CertDirectoryServiceClient dirServiceClient= keyRingService.getCACertDirServiceClient(dnname);
      if(dirServiceClient!=null) {
	log.debug("Adding Dn to CRL Cache  " + dnname + dirServiceClient.getDirectoryServiceURL()
		  +dirServiceClient.getDirectoryServiceType()) ;
	addToCRLCache(dnname,dirServiceClient.getDirectoryServiceURL(),dirServiceClient.getDirectoryServiceType());
      }
      else {
      */
	log.debug("Adding Dn to CRL Cache  " + dnname) ;
	addToCRLCache(dnname,null,0);
      //}
    }
  }

  
  public String getLastModifiedTime(String dnname){
    String timestamp=null;
    if(entryExists(dnname)) {
      CRLWrapper wrapper=null;
      wrapper=(CRLWrapper) crlsCache.get(dnname);
      timestamp=wrapper.getLastModifiedTimestamp();
    }
    return timestamp;   
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
    if (alarmService != null)
      return alarmService.currentTimeMillis();
    else
      return System.currentTimeMillis();
  }
  
  
  public boolean triggerEvent(Object event) {
    log.debug("trigger event is called in CRL Cache "+ event.toString());
    return false;
  }

  public void publishCrlRregistration() {

    Enumeration enum=crlsCache.keys();
    String key=null;
    CRLWrapper wrapper=null;
    CRLAgentRegistration crlagentregistartion=null;
    if(crlsCache.isEmpty()) {
      log.debug("crlsCache is empty :");
    }
    blackboardService.openTransaction();
    CrlRelay crlregrelay=null;
    
    while(enum.hasMoreElements()) {
      key=(String)enum.nextElement();
      wrapper=(CRLWrapper) crlsCache.get(key);
      crlagentregistartion=new CRLAgentRegistration (wrapper.getDN(),wrapper.getCertDirectoryURL(),
						     wrapper.getCertDirectoryType());

      /*Please Note ClusterIdentifier has been hard coded . Mechanism needs to be worked out 
	so that in actual deployment it will be an ABA which targets set of agents that are 
	running to provide CRL updates .
	 
      */
	  
      crlregrelay=crlMgmtService.newCrlRelay(crlagentregistartion,
					     MessageAddress.getMessageAddress("SocietySecurityManager"));
      log.debug(" CRL rely is being published :"+ crlregrelay.toString());
      blackboardService.publishAdd(crlregrelay);
      //blackboardService.closeTransaction();
    }
    blackboardService.closeTransaction();
    
    
  }

  public void setBlackboardService() {
    //log.debug(" setBlackboardService called :");
    blackboardService = (BlackboardService) serviceBroker.getService(this,BlackboardService.class, null);
    AgentIdentificationService agentIdentificationService=
      (AgentIdentificationService) serviceBroker.getService(this,
							    AgentIdentificationService.class,
							    null);
    if(agentIdentificationService!=null){
      log.debug("agentIdentificationService is NOT NULL in setBlackboardService");
    }
														
    SchedulerService schedulerService= 
      (SchedulerService) serviceBroker.getService(this,
						  SchedulerService.class,
						  null);
    if(schedulerService!=null){
      log.debug("schedulerService is NOT NULL in setBlackboardService");
    } 
    
    AlarmService alarmService= 
      (AlarmService) serviceBroker.getService(this,
					      AlarmService.class,
					      null);
    if(alarmService!=null){
      log.debug("salarmService is NOT NULL in setBlackboardService");
    } 
    
    if(blackboardService!=null) {
      crlBlackboardComponent=new CrlCacheBlackboardComponent();
      crlBlackboardComponent.setBindingSite(bindingSite);
      log.debug(" Service broker from binding site :"+bindingSite.getServiceBroker().toString());
      //crlBlackboardComponent.setParameters(null);
      crlBlackboardComponent.setSchedulerService(schedulerService );
      crlBlackboardComponent.setBlackboardService(blackboardService);
      crlBlackboardComponent.setAlarmService(alarmService );
      crlBlackboardComponent.setAgentIdentificationService(agentIdentificationService);
      crlBlackboardComponent.initialize();
      crlBlackboardComponent.load();
      crlBlackboardComponent.start();
    }
    
    if(crlMgmtService==null) {
      log.debug("crlMgmtService is null trying to get the service :");
      if(serviceBroker.hasService(CrlManagementService.class)){
	crlMgmtService = (CrlManagementService) serviceBroker.getService(this,CrlManagementService.class, null); 
      }
      else {
	log.debug("Cannot get CrlManagementService:");
      }
    }
    
    if((blackboardService!=null) && (crlMgmtService!=null )){
      log.debug("Going ot call publishCrlRregistration in setBlackboardService:");
      publishCrlRregistration();
    }
    else {
      log.debug("Either blackboardService/ crlMgmtService is NULL:");
    }
  }

  public void setCrlManagementService(){
    //log.debug(" setCrlManagementService called ");
    if(serviceBroker.hasService(org.cougaar.core.service.DomainService.class)){
      crlMgmtService = (CrlManagementService) serviceBroker.getService(this,CrlManagementService.class, null); 
      if((crlMgmtService!=null)&& (blackboardService!=null)){
	log.debug("publishCrlRregistration called :"); 
	publishCrlRregistration();
      }
    }
    else {
      log.debug("DomainService is not available adding listner  :");
      serviceBroker.addServiceListener(new DomainServiceAvailableListener());
            
    }
  }


         
  private class DomainServiceAvailableListener implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      if(  org.cougaar.core.service.DomainService.class.isAssignableFrom(sc)) {
	//blackboardService = (BlackboardService) serviceBroker.getService(this,BlackboardService.class, null);
	log.debug("Domain Service is available now in CRLCache  going to call set setCrlManagementService ");
	setCrlManagementService();
      }
    }
  }


  private class BlackboardServiceAvailableListener implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      if(  org.cougaar.core.service.BlackboardService.class.isAssignableFrom(sc)) {
	if(blackboardService==null){
	  log.debug("BB Service is available now in CRLCache  going to call setBlackboardService ");
	  setBlackboardService();
	}
      }
         
    }
  }


  private class CrlManagementServiceAvailableListener implements ServiceAvailableListener{
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      if( CrlManagementService.class.isAssignableFrom(sc)) {
	log.info("crlMgmt Service is available now in CRL Cache going to call setCrlManagementService");
	setCrlManagementService();	
      }
    }
  }


  class CrlResponsePredicate implements UnaryPredicate{
    public boolean execute(Object o) {
      boolean ret = false;
      CrlRelay relay=null;
      if (o instanceof  CrlRelay ) {
	relay=(CrlRelay)o;
	if(relay.getResponse()!=null) {
	  return true;
	}
      }
      return ret;
    }
  }

  private class CrlCacheBlackboardComponent extends org.cougaar.util.GenericStateModelAdapter
    implements Component, BlackboardClient  {
    
    private IncrementalSubscription crlresponse;
    private Object parameter = null;
    protected MessageAddress agentId;
    private SchedulerService scheduler;
    protected BlackboardService blackboard;
    protected AlarmService alarmService;
    
    protected String blackboardClientName;
    
    private BindingSite bindingSite;
    private ServiceBroker serviceBroker;
    
    private TriggerModel tm;
    private SubscriptionWatcher watcher;
    
    public CrlCacheBlackboardComponent() { 
    }
  
    /**
     * Called just after construction (via introspection) by the 
     * loader if a non-null parameter Object was specified by
     * the ComponentDescription.
     **/
    public void setParameter(Object param) {
      parameter = param;
    }
  
    /**
     * @return the parameter set by {@link #setParameter}
     **/
    public Object getParameter() {
      return parameter;
    }

    /** 
     * Get any Component parameters passed by the instantiator.
     * @return The parameter specified
     * if it was a collection, a collection with one element (the parameter) if 
     * it wasn't a collection, or an empty collection if the parameter wasn't
     * specified.
     */
    public Collection getParameters() {        
      if (parameter == null) {
	return new ArrayList(0);
      } else {
	if (parameter instanceof Collection) {
	  return (Collection) parameter;
	} else {
	  List l = new ArrayList(1);
	  l.add(parameter);
	  return l;
	}
      }
    }
  
    /**
     * Binding site is set by reflection at creation-time.
     */
    public void setBindingSite(BindingSite bs) {
      bindingSite = bs;
      serviceBroker = bindingSite.getServiceBroker();
    }

    /**
     * Get the binding site, for subclass use.
     */
    protected BindingSite getBindingSite() {
      return bindingSite;
    }
  
    /** 
     * Get the ServiceBroker, for subclass use.
     */
    protected ServiceBroker getServiceBroker() {
      return serviceBroker;
    }

    // rely upon load-time introspection to set these services - 
    //   don't worry about revokation.
    public final void setSchedulerService(SchedulerService ss) {
      scheduler = ss;
    }
    public final void setBlackboardService(BlackboardService bs) {
      blackboard = bs;
    }
    public final void setAlarmService(AlarmService s) {
      alarmService = s;
    }
    public final void setAgentIdentificationService(AgentIdentificationService ais) {
      if (ais != null) {
	agentId = ais.getMessageAddress();
      } else {
	// FIXME: Log something?
      }
    }

    /**
     * Get the blackboard service, for subclass use.
     */
    protected BlackboardService getBlackboardService() {
      return blackboard;
    }

    /**
     * Get the alarm service, for subclass use.
     */
    protected AlarmService getAlarmService() {
      return alarmService;
    }
  
    protected final void requestCycle() {
      tm.trigger();
    }

    //
    // implement GenericStateModel:
    //

    public void initialize() {
      super.initialize();
    }

    public void load() {
      super.load();
    
      // create a blackboard watcher
      this.watcher = 
	new SubscriptionWatcher() {
	  public void signalNotify(int event) {
	    // gets called frequently as the blackboard objects change
	    super.signalNotify(event);
	    requestCycle();
	  }
	  public String toString() {
	    return "ThinWatcher("+CrlCacheBlackboardComponent.this.toString()+")";
	  }
	};

      // create a callback for running this component
      Trigger myTrigger = 
	new Trigger() {
	  String compName = null;
	  private boolean didPrecycle = false;
	  // no need to "sync" when using "SyncTriggerModel"
	  public void trigger() {
	    Thread currentThread = Thread.currentThread();
	    String savedName = currentThread.getName();
	    if (compName == null) compName = getBlackboardClientName();
	    currentThread.setName(compName);
	    awakened = watcher.clearSignal();
	    try {
	      if (didPrecycle) {
		cycle();
	      } else {
		didPrecycle = true;
		precycle();
	      }
	    } finally {
	      awakened = false;
	      currentThread.setName(savedName);
	    }
	  }
	  public String toString() {
	    return "Trigger("+CrlCacheBlackboardComponent.this.toString()+")";
	  }
	};

      // create the trigger model
      this.tm = new SyncTriggerModelImpl(scheduler, myTrigger);

      // activate the blackboard watcher
      blackboard.registerInterest(watcher);

      // activate the trigger model
      tm.initialize();
      tm.load();
    }

    public void start() {
      super.start();
      tm.start();
      // Tell the scheduler to run me at least this once
      requestCycle();
    }

    public void suspend() {
      super.suspend();
      tm.suspend();
    }

    public void resume() {
      super.resume();
      tm.resume();
    }

    public void stop() {
      super.stop();
      tm.stop();
    }

    public void halt() {
      super.halt();
      tm.halt();
    }
  
    public void unload() {
      super.unload();
      if (tm != null) {
	tm.unload();
	tm = null;
      }
      blackboard.unregisterInterest(watcher);
      if (alarmService != null) {
	serviceBroker.releaseService(this, AlarmService.class, alarmService);
	alarmService = null;
      }
      if (blackboard != null) {
	serviceBroker.releaseService(this, BlackboardService.class, blackboard);
	blackboard = null;
      }
      if (scheduler != null) {
	serviceBroker.releaseService(this, SchedulerService.class, scheduler);
	scheduler = null;
      }
    }

    //
    // implement basic "callback" actions
    //

    protected void precycle() {
      log.debug("precycle called in CrlCacheBlackboardComponent"+getBlackboardClientName() ); 
      try {
	blackboard.openTransaction();
	setupSubscriptions();
	log.debug("setupSubscriptions called in CrlCacheBlackboardComponent" ); 
	// run execute here so subscriptions don't miss out on the first
	// batch in their subscription addedLists
	execute();                // MIK: I don't like this!!!
      } catch (Throwable t) {
	System.err.println("Error: Uncaught exception in "+this+": "+t);
	t.printStackTrace();
      } finally {
	blackboard.closeTransaction();
      }
    }      
  
    protected void cycle() {
      // do stuff
      try {
	blackboard.openTransaction();
	if (shouldExecute()) {
	  execute();
	}
      } catch (Throwable t) {
	System.err.println("Error: Uncaught exception in "+this+": "+t);
	t.printStackTrace();
      } finally {
	blackboard.closeTransaction();
      }
    }
  
    protected boolean shouldExecute() {
      return (wasAwakened() || blackboard.haveCollectionsChanged());
    }

    /**
     * Get the local agent's address.
     *
     * Also consider adding a "getNodeIdentifier()" method backed
     * by the NodeIdentificationService.
     */
    protected MessageAddress getAgentIdentifier() {
      return agentId;
    }

    /** @deprecated Use getAgentIdentifier() */
    protected MessageAddress getClusterIdentifier() {
      return getAgentIdentifier();
    }

  
    /** storage for wasAwakened - only valid during cycle().
     **/
    private boolean awakened = false;

    /** true IFF were we awakened explicitly (i.e. we were asked to run
     * even if no subscription activity has happened).
     * The value is valid only within the scope of the cycle() method.
     */
    protected final boolean wasAwakened() { return awakened; }

    // for BlackboardClient use
    public synchronized String getBlackboardClientName() {
      if (blackboardClientName == null) {
	StringBuffer buf = new StringBuffer();
	buf.append(getClass().getName());
	if (parameter instanceof Collection) {
	  buf.append("[");
	  String sep = "";
	  for (Iterator params = ((Collection)parameter).iterator(); params.hasNext(); ) {
	    buf.append(sep);
	    buf.append(params.next().toString());
	    sep = ",";
	  }
	  buf.append("]");
	}
	blackboardClientName = buf.substring(0);
      }
      return blackboardClientName;
    }
  
    public long currentTimeMillis() {
      if (alarmService != null)
	return alarmService.currentTimeMillis();
      else
	return System.currentTimeMillis();
    }
  
    // odd BlackboardClient method -- will likely be removed.
    public boolean triggerEvent(Object event) {
      return false;
    }
  
    public String toString() {
      return getBlackboardClientName();
    }
   
  
    protected void setupSubscriptions(){
      log.debug("setupSubscriptions called :");
      //log.debug("setupSubscriptions of CrlCacheBlackboardComponent called :");
      crlresponse=(IncrementalSubscription)getBlackboardService().subscribe(new CrlResponsePredicate());
    }
  
    /**
     * Called every time this component is scheduled to run.
     */
    protected void execute(){
      log.debug("Execute of CrlCacheBlackboardComponent called :");
      Iterator resiterator=null;
      Collection responsecollection=null;
      CrlRelay responserelay=null;
      CRLWrapper receivedcrl=null;
      String dn=null;
      responsecollection= crlresponse.getChangedCollection();
      resiterator=responsecollection.iterator();
      while(resiterator.hasNext()) {
	responserelay=(CrlRelay)resiterator.next();
	log.debug("Received response :"+ responserelay.toString());
	if(responserelay.getResponse()!=null) {
	  receivedcrl=(CRLWrapper) responserelay.getResponse();
	  dn=receivedcrl.getDN();
	  log.debug("Received response for crl update for DN :"+ dn);
	  Date currentLastmodified=getDateFromUTC(receivedcrl.getLastModifiedTimestamp());
	  Date cacheLastModified=getDateFromUTC(getLastModifiedTime(dn));
	  log.debug("Received Crl last modified date ="+currentLastmodified.toString());
	  if(cacheLastModified!=null)
	    log.debug(" Crl cache last modified date ="+cacheLastModified.toString());
	  if(cacheLastModified!=null) {
	    if(currentLastmodified.after(cacheLastModified)) {
	      log.debug("Updating CRL Cache for DN :"+ dn);
	      updateCRLCache(receivedcrl);
	    }
	    else {
	      log.debug("Received dates are equal in response plugin:");
	    }
	  }
	  else{
	    log.debug("Updating CRL Cache for DN :"+ dn);
	    updateCRLCache(receivedcrl);
	  }
	}
	else{
	  log.debug("Received response for crl update but response was null:");
	}
      }
    }

    private Date getDateFromUTC( String utc ) {
      // utc is in the form of "20010706080000Z". get year,
      // month, day, hour, minute, and second from the utc
      if(utc==null) {
	log.debug("utc is null :");
	return null;
	//Calendar utcTime = Calendar.getInstance();
	//return utcTime.getTime();
      }
      TimeZone tz = TimeZone.getTimeZone("GMT");
      int year   = Integer.parseInt( utc.substring(  0, 4  ));
      int mon    = Integer.parseInt( utc.substring(  4, 6  ));
      int day    = Integer.parseInt( utc.substring(  6, 8  ));
      int hour   = Integer.parseInt( utc.substring(  8, 10 ));
      int minute = Integer.parseInt( utc.substring( 10, 12 ));
      int second = Integer.parseInt( utc.substring( 12, 14 ));
      
      Calendar utcTime = Calendar.getInstance(tz);
      // set calendar to the time
      utcTime.set( year, mon-1 , day, hour, minute, second );
      return utcTime.getTime();
    }
    
  }
}


