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
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.NamingException;
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
//import org.cougaar.core.component.BindingSite;
import org.cougaar.util.ConfigFinder;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.SchedulerService;
import org.cougaar.core.service.AlarmService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.CommunityChangeListener;
import org.cougaar.core.service.community.CommunityChangeEvent;
import org.cougaar.core.service.community.Entity;
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

import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.core.mts.MessageAddress;

// Cougaar security services
import org.cougaar.core.security.crlextension.x509.extensions.*;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.crypto.*;
import  org.cougaar.core.security.crypto.crl.blackboard.*;
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.util.*;

final public class CRLCache
  implements Runnable, CRLCacheService, BlackboardClient
{

  private SecurityPropertiesService secprop = null;
  //private DirectoryKeyStoreParameters param;
  //private KeyStore caKeystore = null; 
  private Hashtable crlsCache = new Hashtable(50);
  private long sleep_time=60000l; // Check CRL every minute by default

  private ServiceBroker serviceBroker;
  private LoggingService log;
  private CommunityService _communityService;
  private ConfigParserService configParser = null; 
  private NodeConfiguration nodeConfiguration;
  
  protected String blackboardClientName;
  protected AlarmService alarmService;
  
/** How long do we wait before retrying to send a certificate signing
 * request to a certificate authority? */
  //private long crlrefresh = 10;
  private BlackboardService blackboardService=null;
  private CrlManagementService crlMgmtService=null;
  //private IncrementalSubscription crlresponse;
//  private BindingSite bindingSite=null;
  private CrlCacheBlackboardComponent crlBlackboardComponent=null;
  private CertificateCacheService cacheservice=null;
  private KeyRingService keyRingService=null;
  
  private Collection _mySecurityCommunities = null;
  private final String CRL_Provider_Role="CrlProvider";
  private MessageAddress myAddress;
  private boolean _listening = false;
  private boolean _crlRegistered = false;
  private Object _blackboardLock = new Object();
  
  public CRLCache(ServiceBroker sb){
    serviceBroker = sb;
    //bindingSite=bs;
    log = (LoggingService)
      serviceBroker.getService(this, LoggingService.class, null);
    secprop = (SecurityPropertiesService)serviceBroker.getService(this,
                                                                  SecurityPropertiesService.class, 
                                                                  null);
    //this.keystore=dkeystore;
    log.debug("Crl cache being initialized  ++++++++++");
    long poll = 0;
    try {
      poll = (Long.valueOf(secprop.getProperty(secprop.CRL_POLLING_PERIOD))).longValue() * 1000;
    } catch (Exception e) {
      // poll will be == 0, so ok.
    }
    if (poll > 0) {
      setSleepTime(poll);
    }
    configParser = (ConfigParserService)
      serviceBroker.getService(this, ConfigParserService.class, null);

    if (secprop == null) {
      throw new RuntimeException("unable to get security properties service");
    }
    if (configParser == null) {
      throw new RuntimeException("unable to get config parser service");
    }
    SecurityPolicy[] sp =configParser.getSecurityPolicies(CryptoClientPolicy.class);
    
    CryptoClientPolicy cryptoClientPolicy = (CryptoClientPolicy) sp[0];
    
    if (cryptoClientPolicy == null || 
        cryptoClientPolicy.getCertificateAttributesPolicy() == null) {
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
    
    String nodeDomain = cryptoClientPolicy.getCertificateAttributesPolicy().domain;
    nodeConfiguration = new NodeConfiguration(nodeDomain, serviceBroker);
    
    cacheservice = (CertificateCacheService)
      serviceBroker.getService(this, CertificateCacheService.class, null);
    keyRingService = (KeyRingService)
      serviceBroker.getService(this, KeyRingService.class, null);
    blackboardService = (BlackboardService)
      serviceBroker.getService(this, BlackboardService.class, null);
    crlMgmtService=(CrlManagementService)
      serviceBroker.getService(this, CrlManagementService.class, null);
    _communityService = (CommunityService)
      serviceBroker.getService(this,CommunityService.class, null);
    AgentIdentificationService ais = (AgentIdentificationService)
      serviceBroker.getService(this, AgentIdentificationService.class, null);
    if (ais != null) {
      myAddress = ais.getMessageAddress();
      serviceBroker.releaseService(this, AgentIdentificationService.class,
                                   ais);
    }

    setServices();

    if (cacheservice == null || keyRingService == null ||
        blackboardService == null || crlMgmtService == null ||
        myAddress == null || _communityService == null) {
      ServiceAvailableListener listener = new ListenForServices();
      serviceBroker.addServiceListener(listener);
      if (log.isDebugEnabled()) {
        log.debug("adding service listener. cacheservice=" + cacheservice +
                  ", keyRingService=" + keyRingService + 
                  ", blackboardService=" + blackboardService +
                  ", crlMgmtService=" + crlMgmtService +
                  ", myAddress=" + myAddress +
                  ", communityService=" + _communityService);
      }
    }
  }
  
  public void startThread() {
    Thread td=new Thread(this,"crlthread");
    td.setPriority(Thread.NORM_PRIORITY);
    td.start();
  }

  public void addToCRLCache(String dnname) {
    if (log.isDebugEnabled()) {
      log.debug("addToCRLCache  -  "+ dnname );
    }
    CRLWrapper wrapper=null;

    if (!entryExists(dnname)) {
      wrapper=new CRLWrapper(dnname);//,certcache);
      crlsCache.put(dnname,wrapper);
      if ((blackboardService != null) && (crlMgmtService != null)) {
	CRLAgentRegistration crlagentregistartion = 
          new CRLAgentRegistration(dnname);
        AttributeBasedAddress aba = null;
        CrlRelay crlregrelay = null;

        if (_mySecurityCommunities != null && 
            !_mySecurityCommunities.isEmpty()) {
	  Iterator it = _mySecurityCommunities.iterator();
          synchronized (_blackboardLock) {
            try {
          blackboardService.openTransaction();
	  while (it.hasNext()) {
	    Community community = (Community) it.next();
            aba=AttributeBasedAddress.
	      getAttributeBasedAddress(community.getName(),
				       "Role",
				       CRL_Provider_Role); 
            crlregrelay=crlMgmtService.newCrlRelay(crlagentregistartion,
                                                   aba);
            if (log.isDebugEnabled()) {
              log.debug(" CRL relay is being published :" +
                        crlregrelay.toString());
            }
            blackboardService.publishAdd(crlregrelay);
          }
            } finally {
          blackboardService.closeTransaction();
            }
          }
        } else {
          if (log.isDebugEnabled()) {
            log.debug("No info about my security community " + 
                      myAddress.toString()); 
          }
        }
      } else {
        log.debug("blackboardService / crlMgmtService is NULL:");
      }
    } else {
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
      log.debug("CRL CACHE THREAD IS RUNNING +++++++++++++++++++++++++++++++++++++++++");
      try {
	Thread.sleep(sleep_time);
      } catch(InterruptedException interruptedexp) {
	interruptedexp.printStackTrace();
      }
      String dnname=null;
      Enumeration enumkeys =crlsCache.keys();
      while(enumkeys.hasMoreElements()) {
	dnname=(String)enumkeys.nextElement();
	updateCRLCache(dnname);
      }
      enumkeys=crlsCache.keys();
      while(enumkeys.hasMoreElements()) {
	dnname=(String)enumkeys.nextElement();
	if(dnname!=null) {
	  updateCRLInCertCache(dnname);
	}
	else {
          log.warn("Dn name is null in thread of crl cache :");
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
    while(iter.hasNext()) {
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
	log.warn("Unable to set crl in cache for :"+distingushname ,exp);
      }
      String lastmodified=wrapperFromDirectory.getLastModifiedTimestamp();
      if(lastmodified !=null) {
        wrapper.setLastModifiedTimestamp(lastmodified);
      }
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
	    //CertificateIssuerExtension ciext=new CertificateIssuerExtension( new Boolean(false),obj);
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
    if(cacheservice==null) {
      log.warn("Unable to get Certificate cache Service in updateCRLEntryInCertCache");
    }
    subjectDN=null;
    if(cacheservice!=null) {
      subjectDN=cacheservice.getDN(crlkey);
    }
    if(subjectDN==null) {
       // need to store the revoked cert information even though
      // we may not have received the cert yet. Otherwise there
      // is a time window for a revoked cert to get into the 
      // system.  
      cacheservice.addToRevokedCache(actualIssuerDN, bigint);
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

  private void initCRLCacheFromKeystore()
    throws KeyStoreException {
    //String s=null;
    X509Certificate certificate=null;
    String dnname=null;
    log.debug("initCRLCacheFromKeystore called :");
    
    if(keyRingService==null) {
      log.error("Unable to get  Key Ring Service in initCRLCacheFromKeystore CRL cache willl register for KeyRing Service  ");
      return;
    }
    /*
      for(Enumeration enumeration = aKeystore.aliases(); enumeration.hasMoreElements(); ) {
      s = (String)enumeration.nextElement();
      certificate =(X509Certificate) aKeystore.getCertificate(s);
    */
    X509Certificate trustedcerts[] = cacheservice.getTrustedIssuers();
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
      addToCRLCache(dnname);
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

  public void publishCrlRegistration() {

//     ensureSecurityCommunities();

    Enumeration crlKeys = crlsCache.keys();
    String key=null;
    CRLWrapper wrapper=null;
    CRLAgentRegistration crlagentregistartion=null;
    if(crlsCache.isEmpty()) {
      log.debug("crlsCache is empty :");
    }
    CrlRelay crlregrelay=null;

    while(crlKeys.hasMoreElements()) {
      key     = (String)crlKeys.nextElement();
      wrapper = (CRLWrapper) crlsCache.get(key);
      crlagentregistartion =
        new CRLAgentRegistration(wrapper.getDN(),
                                 wrapper.getCertDirectoryURL(),
                                 wrapper.getCertDirectoryType());
      AttributeBasedAddress aba=null;

      if (_mySecurityCommunities != null && !_mySecurityCommunities.isEmpty()) {
	Iterator it = _mySecurityCommunities.iterator();

        synchronized (_blackboardLock) {
          try {
        blackboardService.openTransaction();
	while (it.hasNext()) {
          Community community = (Community) it.next();
          aba=AttributeBasedAddress.
	    getAttributeBasedAddress(community.getName(),
				     "Role",
				     CRL_Provider_Role);
          
          crlregrelay=crlMgmtService.newCrlRelay(crlagentregistartion,
                                                 aba);
          log.debug(" CRL relay is being published :"+ crlregrelay.toString());
          blackboardService.publishAdd(crlregrelay);
        }
          } finally {
	    blackboardService.closeTransaction();
          }
        }
      }
    }
  }

  private synchronized void setSecurityCommunity() {
    log.debug("Setting Security Communities");
    CommunityResponseListener listener = new GetCommunities();
    Collection communities = 
      _communityService.searchCommunity(
	null, "(CommunityType=" +
	CommunityServiceUtil.SECURITY_COMMUNITY_TYPE + ")", 
	true, Community.COMMUNITIES_ONLY, 
	listener);
    if (communities == null) {
      _listening = true;
    } else {
      setMySecurityCommunity(communities);
    }
    CommunityChangeListener changeListener = new GetChangedCommunities();
    _communityService.addListener(changeListener);
  }

  private void setMySecurityCommunity(Collection c) {
    _mySecurityCommunities = c;
    if (_mySecurityCommunities.isEmpty()) {
      log.warn("Agent is NOT part of ANY SECURITY COMMUNITY:" +
               myAddress);
    } else if (log.isDebugEnabled()) {
      log.debug("Agent " + myAddress + " security communities: " +
                _mySecurityCommunities);
    }
  }

  public void startCrlPoll() {
    log.debug("Starting CRL Poll");
    SchedulerService schedulerService= 
      (SchedulerService) serviceBroker.getService(this,
						  SchedulerService.class,
						  null);
    if(schedulerService!=null){
      log.debug("schedulerService is NOT NULL in startCrlPoll");
    } 
    
    AlarmService alarmService= 
      (AlarmService) serviceBroker.getService(this,
					      AlarmService.class,
					      null);
    if(alarmService!=null){
      log.debug("salarmService is NOT NULL in startCrlPoll");
    } 
    
    if(blackboardService!=null) {
      crlBlackboardComponent=new CrlCacheBlackboardComponent();
      crlBlackboardComponent.setSchedulerService(schedulerService );
      crlBlackboardComponent.setBlackboardService(blackboardService);
      crlBlackboardComponent.setAlarmService(alarmService );
      crlBlackboardComponent.setAddress(myAddress);
      crlBlackboardComponent.initialize();
      crlBlackboardComponent.load();
      crlBlackboardComponent.start();
    }
    
    serviceBroker.releaseService(this,
                                 SchedulerService.class,
                                 schedulerService);
    serviceBroker.releaseService(this,
                                 AlarmService.class,
                                 alarmService);
  }

  private synchronized void setServices() {
    if (_communityService != null &&
        _mySecurityCommunities == null && !_listening) {
      setSecurityCommunity();
    }
    if (!_crlRegistered && 
        crlMgmtService != null && blackboardService != null &&
        _mySecurityCommunities != null) {
      publishCrlRegistration();
    }
    if (myAddress != null && blackboardService != null) {
      startCrlPoll();
    }
        
  }
  
  private class GetCommunities implements CommunityResponseListener {
    public void getResponse(CommunityResponse response) {
      Object resp = response.getContent();
      if (!(resp instanceof Set)) {
        String errorString = "Unexpected community response class:" +
          resp.getClass().getName() + " - Should be a Set";
        log.error(errorString);
        throw new RuntimeException(errorString);
      }

      setMySecurityCommunity((Set)resp);
      _listening = false;
      setServices(); // try that again...
    }
  }

  private class GetChangedCommunities implements CommunityChangeListener {
    public void communityChanged(CommunityChangeEvent event) {
      Community community = event.getCommunity();
      try {
	Attributes attrs = community.getAttributes();
	Attribute attr = attrs.get("CommunityType");
	if (attr != null) {
	  for (int i = 0; i < attr.size(); i++) {
	    Object type = attr.get(i);
	    if (type.equals(CommunityServiceUtil.SECURITY_COMMUNITY_TYPE)) {
	      if (log.isInfoEnabled()) {
		log.info("Adding security community: " +
		  community.getName());
	      }
	      synchronized (_mySecurityCommunities) {
		_mySecurityCommunities.add(community);
	      }
	    }
	  }
	}
      } catch (NamingException e) {
	throw new RuntimeException("This should never happen");
      }
    }
    public String getCommunityName() {
      return null;  // all MY communities
    }
  }

  private class ListenForServices
    implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      ServiceBroker sb = ae.getServiceBroker();
      if ( sc == AgentIdentificationService.class ) {
	log.info(" AgentIdentification Service is available now in CRL Cache going to call setmyCommunity");
        AgentIdentificationService ais = (AgentIdentificationService)
          sb.getService(this, AgentIdentificationService.class, null);
        myAddress = ais.getMessageAddress();
        sb.releaseService(this, AgentIdentificationService.class, ais);
      } else if ( sc == CertificateCacheService.class ) {
        cacheservice = (CertificateCacheService)
          sb.getService(CRLCache.this, CertificateCacheService.class, null);
      } else if ( sc == KeyRingService.class ) {
        keyRingService = (KeyRingService)
          sb.getService(CRLCache.this, KeyRingService.class, null);
      } else if ( sc == BlackboardService.class ) {
        blackboardService = (BlackboardService)
          sb.getService(CRLCache.this, BlackboardService.class, null);
      } else if ( sc == CrlManagementService.class ) {
        crlMgmtService=(CrlManagementService)
          sb.getService(CRLCache.this, CrlManagementService.class, null);
      } else if ( sc == CommunityService.class ) {
        _communityService = (CommunityService)
          serviceBroker.getService(CRLCache.this, 
                                   CommunityService.class, null);
//       } else if ( sc == DomainService.class ) {
//         _domainService = (DomainService)
//           serviceBroker.getService(this, DomainService.class, null);
      }
      setServices(); 
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

  private class CrlCacheBlackboardComponent
    extends org.cougaar.util.GenericStateModelAdapter
    implements Component, BlackboardClient  {
    
    private IncrementalSubscription crlresponse;
    private Object parameter = null;
    protected MessageAddress agentId;
    private SchedulerService scheduler;
    protected BlackboardService blackboard;
    protected AlarmService alarmService;
    
    protected String blackboardClientName;
    
    //private BindingSite bindingSite;
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
    /*
    public void setBindingSite(BindingSite bs) {
      bindingSite = bs;
      serviceBroker = bindingSite.getServiceBroker();
    }
    */
    /**
     * Get the binding site, for subclass use.
     */
/*
    protected BindingSite getBindingSite() {
      return bindingSite;
    }
*/
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
    public final void setAddress(MessageAddress addr) {
      agentId = addr;
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
      synchronized (_blackboardLock) {
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
    }      
  
    protected void cycle() {
      // do stuff
      synchronized (_blackboardLock) {
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
	  Date currentLastmodified=DateUtil.getDateFromUTC(receivedcrl.getLastModifiedTimestamp());
          log.debug("Received Crl last modified date ="+currentLastmodified.toString());
          String currentModifiedInCache=getLastModifiedTime(dn);
	  Date cacheLastModified=DateUtil.getDateFromUTC(currentModifiedInCache);
          if(cacheLastModified!=null){
	    log.debug(" Crl cache last modified date ="+cacheLastModified.toString());
          }
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
   
  } 
}



  
