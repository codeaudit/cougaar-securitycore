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
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.crlextension.x509.extensions.*;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

public class CRLCache implements Runnable
{
  private SecurityPropertiesService secprop = null;

  private Hashtable crlsCache = new Hashtable(50);
  private long sleep_time=60000l; // Check CRL every minute by default

  //private boolean debug =false;
  private DirectoryKeyStore keystore=null;
  private CertificateCache certcache=null;
  private CertDirectoryServiceClient certFinder;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  /** How long do we wait before retrying to send a certificate signing
   * request to a certificate authority? */
  private long crlrefresh = 10;

  public CRLCache(DirectoryKeyStore dkeystore, ServiceBroker sb)
  {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    secprop = (SecurityPropertiesService)
      serviceBroker.getService(this,
			       SecurityPropertiesService.class, null);

    this.keystore=dkeystore;
    if(log.isDebugEnabled()) {
      log.debug("Crl cache being initialized:::++++++++++");
    }
    long poll = 0;
    try {
      poll = (Long.valueOf(secprop.getProperty(secprop.CRL_POLLING_PERIOD))).longValue() * 1000;
    }
    catch (Exception e) {}
    if (poll != 0) {
      setSleepTime(poll);
    }
  }

  public void startThread() {
    Thread td=new Thread(this,"crlthread");
    td.setPriority(Thread.NORM_PRIORITY);
    td.start();
  }

  public void add(String dnname)
  {
    if(log.isDebugEnabled())
      log.debug(" dn name being added ::+++++++++++++++"+ dnname);

    CRLWrapper wrapper=null;
    if(!entryExists(dnname)) {
      wrapper=new CRLWrapper(dnname);//,certcache);
      crlsCache.put(dnname,wrapper);
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

  private boolean entryExists(String dnname)
  {
    return crlsCache.containsKey(dnname);
  }

  /** Lookup Certificate Revocation Lists */
  public void run() {
    Thread td=Thread.currentThread();
    td.setPriority(Thread.MIN_PRIORITY);
    while(true) {
      if(log.isDebugEnabled())
	log.debug("**************** CRL CACHE THREAD IS RUNNING ***********************************");
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
    
    if (keystore.certCache == null) {
      log.info("Certificate cache not initialized yet");
      return;
    }
    List certList = keystore.certCache.getValidCertificates(name);
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

    // check whether it is specified in the policy
    CertDirectoryServiceClient certificateFinder = keystore.getCACertDirServiceClient(distingushname);
    // check whether it is found in trust chain
    if (certificateFinder == null) {
      certificateFinder = certstatus.getCertFinder();
      if (log.isDebugEnabled())
        log.debug("Get cert finder from status: " + certificateFinder);
    }
    // pretty much not found, check it is in the naming service
/*
    if (certificateFinder == null) {
      try {
	certificateFinder = keystore.getCertDirectoryServiceClient(distingushname);
      }
      catch (Exception e) {
	log.warn("Unable to get certificatels finder");
      }
    }
*/

    crlIssuerCert=(X509Certificate)certstatus.getCertificate();
    crlIssuerPublickey=crlIssuerCert.getPublicKey();
    if(certificateFinder== null) {
      if(log.isWarnEnabled())
	log.warn("No certificateFinder present in Directory keystore in update CRL :"+distingushname);
    }
    try {
      crl=certificateFinder.getCRL(distingushname);
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
      keystore.checkCertificateTrust(crlIssuerCert);
    }
    catch(Exception exp) {
      exp.printStackTrace();
      return;
    }
    if(crl!=null) {
      wrapper=(CRLWrapper) crlsCache.get(distingushname);
      wrapper.setCRL(crl);
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
	  try
	    {
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
	      for(int j = 0; j < i; j++)
                Array.setByte(obj, j, abyte0[j]);

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

    // need to store the revoked cert information even though
    // we may not have received the cert yet. Otherwise there
    // is a time window for a revoked cert to get into the 
    // system. 
    keystore.certCache.addToRevokedCache(actualIssuerDN, bigint);

    subjectDN=keystore.certCache.getDN(crlkey);
    if(subjectDN==null) {

      return;
    }
    if(log.isDebugEnabled())
      log.debug(" Got the dn for the revoked cert in CRL Caches updateCRLEntryInCertCache :"+subjectDN);
    keystore.certCache.revokeStatus(bigint,actualIssuerDN,subjectDN);

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

  public CRLWrapper getCRL(String dnname)
  {
    return null;
  }
  public boolean isCertificateInCRL(X509Certificate subjectCertificate, String IssuerDN)
  {
    boolean incrl=false;
    CRLWrapper crlwrapper=null;
    X509CRL crl=null;
    if(entryExists(IssuerDN)) {
      crlwrapper=(CRLWrapper)crlsCache.get(IssuerDN);
      crl=crlwrapper.getCRL();

    }
    return incrl;
  }


}

