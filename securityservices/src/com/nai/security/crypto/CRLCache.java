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
import com.nai.security.crlextension.x509.extensions.CertificateIssuerExtension;
import com.nai.security.crypto.ldap.CertDirectoryServiceClient;
import com.nai.security.util.CryptoDebug;


public class CRLCache implements Runnable
{
  private Hashtable crlsCache = new Hashtable(50);
  private long sleep_time=2000l; 
  
  //private boolean debug =false;
  private DirectoryKeyStore keystore=null;
  private CertificateCache certcache=null;
  private CertDirectoryServiceClient certFinder;

  /** How long do we wait before retrying to send a certificate signing
   * request to a certificate authority? */
  private long crlrefresh = 10;

  public CRLCache(DirectoryKeyStore dkeystore) 
  {
    this.keystore=dkeystore;
    if(CryptoDebug.crldebug) {
      System.out.println("Crl cache being initialized:::++++++++++");
    }
    Thread td=new Thread(this,"crlthread");
    td.setPriority(Thread.NORM_PRIORITY);
    td.start();
  }
  public void add(String dnname)
  {
    if(CryptoDebug.crldebug)
      System.out.println(" dn name being added ::+++++++++++++++"+ dnname);
    
    CRLWrapper wrapper=null;
    if(!entryExists(dnname)) {
      wrapper=new CRLWrapper(dnname);//,certcache);
      crlsCache.put(dnname,wrapper);
    }
    else {
      if(CryptoDebug.crldebug) {
	System.out.println("Warning !!! Entry already exists for dnname :" +dnname);
      }
    }
  }
  
  public void setSleepTime(long sleeptime) {
    sleep_time=sleeptime;
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
    while(true) {
      if(CryptoDebug.crldebug)
	System.out.println("**************** CRL CACHE THREAD IS RUNNING ***********************************");
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
      Thread td=Thread.currentThread();
     
      td.setPriority(Thread.MIN_PRIORITY);
      enumkeys=crlsCache.keys();
      for(;enumkeys.hasMoreElements();) {
	dnname=(String)enumkeys.nextElement();
	if(dnname!=null)
	  updateCRLInCertCache(dnname);
	else { 
	  if(CryptoDebug.crldebug)
	    System.out.println("Warning !!! dn name is null in thread of crl cache :");
	}
      }
    }
  }

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


  private void updateCRLCache(String distingushname) {
    if(CryptoDebug.crldebug) {
      System.out.println(" Updating crl cache for :"+distingushname);
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
      exp.printStackTrace();
    }
    CertificateStatus certstatus=keystore.certCache.getCertificate(name);
    crlIssuerCert=(X509Certificate)certstatus.getCertificate();
    crlIssuerPublickey=crlIssuerCert.getPublicKey();
    if(keystore.certificateFinder== null) {
      if(CryptoDebug.crldebug)
	System.out.println(" Error !!!!! No  certificateFinder present in Directory keystore in update CRL :"+distingushname); 
    }
    crl=keystore.certificateFinder.getCRL(distingushname);
    if(crl==null) {
      if(CryptoDebug.crldebug) {
	System.out.println("Warning !!!!  No crl present for :"+distingushname);
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
    if(CryptoDebug.crldebug) {
      System.out.println("crl enty in updateCRLEntryInCertCache is :"+crlentry.toString());
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
	  if(CryptoDebug.crldebug)
	    System.out.println(" Got oid for non critical extension in updateCRLEntryInCertCache is :"+oid);
	}
	if(oid!=null) {
	  issuerbytes=crlentry.getExtensionValue(oid);
	  
	  if(issuerbytes==null) {
	    
	    System.out.println(" Got issuerbytes as null for oid :" +oid );
	  }
	  try
	    {
	      if(CryptoDebug.crldebug)
		System.out.println(" going to get extension class in CRL Caches updateCRLEntryInCertCache :");
	      Class class1 = OIDMap.getClass(new ObjectIdentifier(oid));
	      if(class1 == null) {
		if(CryptoDebug.crldebug)
		  System.out.println(" Class was null in CRL Caches updateCRLEntryInCertCache :");
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
		GeneralNames gn=(GeneralNames) certattrset.get(CertificateIssuerExtension.ISSUERNAME);
		if(CryptoDebug.crldebug)
		  System.out.println(" gneral names are in CRL Caches updateCRLEntryInCertCache  :"+gn.toString());
		if(gn.size()==1){
		  GeneralName  name=(GeneralName)gn.elementAt(0);
		  if(name.getType()==4)  {
		    if(CryptoDebug.crldebug)
		      System.out.println("got actual data from extension in  CRL Caches updateCRLEntryInCertCache :"+name.toString());
		    actualIssuerDN=name.toString();
		  }
		  else
		    System.out.println("Error !!!! not x500 name ");
		}
	      }
	      else {
		System.out.println("Warning !!!!!!  not instance of CertificateIssuerExtension");
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
	if(CryptoDebug.crldebug)
	  System.out.println("Error in getting extensions for crlentry :"+crlentry.toString());
      }
      
    }
    else {
      actualIssuerDN=Issuerdn;
    }
    
    crlkey=new CRLKey(bigint,actualIssuerDN);
    if(CryptoDebug.crldebug) {
      System.out.println("Going to look for key  in CRL Caches updateCRLEntryInCertCache  :"+crlkey.toString());
      System.out.println(" cache contains  in CRL Caches updateCRLEntryInCertCache:");
     
      //keystore.certCache.printbigIntCache();
      System.out.println("");
      System.out.println("");
      System.out.println("");
    }
    subjectDN=keystore.certCache.getDN(crlkey);
    if(subjectDN==null) {
      
      return;
    }
    if(CryptoDebug.crldebug)
      System.out.println(" Got the dn for the revoked cert in CRL Caches updateCRLEntryInCertCache :"+subjectDN);
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

