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

package org.cougaar.core.security.crypto.blackboard;

import java.util.*;
import java.io.*;
import java.security.cert.X509Certificate;
import java.security.*;
import java.security.cert.Certificate;
import sun.security.pkcs.*;
import sun.security.x509.*;
import javax.naming.NameAlreadyBoundException;

// Cougaar core services
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.blackboard.BlackboardClient;

// Cougaar security services
import org.cougaar.core.security.services.util.CACertDirectoryService;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.crypto.CertificateRevocationStatus;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.naming.CertificateEntry;
import org.cougaar.core.security.naming.CACertificateEntry;


public class CACertDirectoryServiceImpl  implements 
CACertDirectoryService, BlackboardClient  {

  private ServiceBroker _serviceBroker;
  private BlackboardService _blackboardService;
  private LoggingService _log;
  private CertificateBlackboardStore _certStore = new CertificateBlackboardStore();
  //private Hashtable _certStore = new Hashtable();
  private boolean bbAvailable = false;

  public CACertDirectoryServiceImpl(ServiceBroker sb) {
    _serviceBroker = sb;
    _log = (LoggingService)_serviceBroker.getService
      (this, LoggingService.class, null);

    BlackboardService bbs = (BlackboardService)
      _serviceBroker.getService(this,
			       BlackboardService.class,
			       null);
    if(bbs==null) {
      if (_log.isDebugEnabled()) {
	_log.debug("Adding service listner for blackboard service :");
      }
      _serviceBroker.addServiceListener(new BlackboardServiceAvailableListener());
    }
    else {
      if (_log.isDebugEnabled()) {
	_log.debug("acquired blackboard service :");
      }
      setBlackboardService();
    }
  }

  /**
   * Publish a certificate (managed by a CA) in the blackboard.
   * The certificate is assumed to be valid.
   */
  public void publishCertificate(X509Certificate cert, int type, PrivateKey privatekey) {
    if (_log.isDebugEnabled()) {
      _log.debug("Publish certificate: " + cert.toString());
    }
    // Assume the certificate is valid if we publish it.
    CertificateRevocationStatus certStatus = CertificateRevocationStatus.VALID;
    CertificateType certType = null;
    switch (type) {
    case CertificateUtility.CACert:
      certType = CertificateType.CERT_TYPE_CA;
      break;
    default:
      certType = CertificateType.CERT_TYPE_END_ENTITY;
    }
    CertificateEntry certEntry = new CertificateEntry(cert,
						      certStatus, certType);
    publishCertificate(certEntry);
  }

  /**
   * Publish a certificate (managed by a CA) in the blackboard
   */
  public void publishCertificate(CertificateEntry certEntry) {
    String dnname = certEntry.getCertificate().getSubjectDN().getName();
    if (_log.isDebugEnabled()) {
      _log.debug("Publish certificate: " + dnname);
    }

    synchronized(_certStore) {
      List certList = (List)_certStore.get(dnname);
      if (certList == null) {
	certList = new ArrayList();
      }
      // indexOf only compares by reference, but publishCertificate(Certificate...)
      // creates a new one every time it is called
      //int index = certList.indexOf(certEntry);
      int index = -1;
      PublicKey pubKey = certEntry.getCertificate().getPublicKey();
      for (int i = 0; i < certList.size(); i++) {
        CertificateEntry entry = (CertificateEntry)certList.get(i);
        if (entry.getCertificate().getPublicKey().equals(pubKey)) {
          // Entry is being modified
          index = i;
          certList.set(index, certEntry);
          break;
        }
      }
      if (index == -1) {
	// New entry
	certList.add(certEntry);
      }
      /*
      else {
	// Entry is being modified
	certList.set(index, certEntry);
      }
      */
      // Add entry for DN and Unique ID so that we can search using both strings
      _certStore.put(dnname, certList);
      _certStore.put(certEntry.getUniqueIdentifier(), certEntry);
    }
    updateBlackBoard();

    if (certEntry.getCertificateType() == CertificateType.CERT_TYPE_CA 
      && certEntry instanceof CACertificateEntry) {
      publishCA((CACertificateEntry)certEntry);
    }
  }

  private synchronized void updateBlackBoard() {
    if (_blackboardService == null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Blackboard service not yet available");
      }
      return;
    }

    if (!bbAvailable) {
      if (_log.isDebugEnabled()) {
        _log.debug("Blackboard service started but not yet rehydrated.");
      }
      return;
    }

    try {
      _blackboardService.openTransaction();
      _blackboardService.publishChange(_certStore);
    }
    catch (Exception e) {
      _log.error("Failed to publish change to blackboard: ", e);
    }
    finally {
      _blackboardService.closeTransaction();
    }
    try {
      // Persist the blackboard so that keys generated by the CA are not accidentaly lost
      // by an agent crash.
      _blackboardService.persistNow();
    }
    catch (Exception e) {
      _log.info("Persistence is not enabled. Certificates will not be persisted");
    }
  }

  /**
   * Return a list of all the certificates managed by the CA, including the CA itself.
   */
  public List getAllCertificates() {
    if (_log.isDebugEnabled()) {
      _log.debug("Get all certificates, cache size " + _certStore.size());
    }
    Enumeration enum = _certStore.elements();
    List completeList = new ArrayList();
    while (enum.hasMoreElements()) {
      Object o = enum.nextElement();
      if (o instanceof List) {
	completeList.addAll((List)o);
      }
    }
    return completeList;
  }

  /**
   * Find a list of certificates matching a distinguished name.
   * @param identifier - The distinguished name of the certificate to look for.
   */
  public List findCertByDistinguishedName(String distinguishedName) {
    if (_log.isDebugEnabled()) {
      _log.debug("Get certificates for " + distinguishedName);
    }
    List certList = (List)_certStore.get(distinguishedName);
    return certList;
  }

  /**
   * Find a certificate given its unique identifier.
   * @param identifier - The unique identifier of the certificate to look for.
   */
  public CertificateEntry findCertByIdentifier(String uniqueIdentifier) {
    if (_log.isDebugEnabled()) {
      _log.debug("Get certificates for " + uniqueIdentifier);
    }
    CertificateEntry certEntry = (CertificateEntry)_certStore.get(uniqueIdentifier);
    return certEntry;
  }

  /** Set the blackboard service and initialize the Certificate
   *  Blackboard Store.
   */
  private final void setBlackboardService() {
    _blackboardService = (BlackboardService)
      _serviceBroker.getService(this,BlackboardService.class, null);
  }

  public synchronized void refreshBlackboard() {
    if (bbAvailable) {
      if (_log.isDebugEnabled()) {
        _log.debug("BB already refreshed.");
      }
      return;
    }

    if (_log.isDebugEnabled()) {
      _log.debug("Refreshing cert store with entries from BB.");
    }

    if (_blackboardService == null) {
      throw new RuntimeException("Blackboard service not available "
        + "but refreshBlackboard is called.");
    }

    Collection collection = null;
    //Hashtable bbstore = null;
    CertificateBlackboardStore bbstore = null;
    if(_blackboardService.didRehydrate()) {
      // Retrieve persisted instance of the Certificate Blackboard Store.
      // There should be only one instance of the the Certificate Store.
      try {
        _blackboardService.openTransaction();
        collection =
          _blackboardService.query(new CertificateBlackboardStorePredicate());
      }
      catch (Exception e) {
        _log.error("Failed to query blackboard: ", e);
      }
      finally {
        _blackboardService.closeTransaction();
      }
      if (collection.size() > 1) {
	throw new RuntimeException
	  ("Can support at most one CertificateBlackboardStore. Current items:" + collection.size());
      }
      if (collection.isEmpty()) {
	collection = null;
      }
      else {
	Iterator it = collection.iterator();
        // bb should be started before CA servlet becomes available
        // to issue certificates
	//_certStore = (Hashtable) it.next();
        bbstore = (CertificateBlackboardStore)it.next();

        if (_log.isDebugEnabled()) {
          _log.debug("Found rehydrated cert store, size " + bbstore.size()
            + ", published cache size " + _certStore.size());
        }
        for (Enumeration en = _certStore.keys(); en.hasMoreElements(); ) {
          String key = (String)en.nextElement();
          Object value = _certStore.get(key);
          // if unique id, simply overwrite it
          if (value instanceof CertificateEntry) {
            bbstore.put(key, value);
          }
          else if (value instanceof List) {
            // need to check whether the entry already exist, if so overwrite it, else add
            List oldlist = (List)bbstore.get(key);
            if (oldlist == null) {
              bbstore.put(key, value);
            }
            else {
              // old certificate entries should not be able to be changed before BB comes up
              // they won't have access to revoke certificates
            }
          }
          else {
            _log.warn("Unknown type found in cert store: " + value);
          }
        }
        _certStore = bbstore;
        updateBlackBoard();
      }
    }
    if (!_blackboardService.didRehydrate() || collection == null) {
      if (_log.isDebugEnabled()) {
        _log.debug("adding cert store to BB");
      }
      try {
        _blackboardService.openTransaction();
        _blackboardService.publishAdd(_certStore);
      }
      catch (Exception e) {
        _log.error("Failed to add to blackboard: ", e);
      }
      finally {
        _blackboardService.closeTransaction();
      }
      try {
        // Persist the blackboard so that keys generated by the CA are not accidentaly lost
        // by an agent crash.
        _blackboardService.persistNow();
      }
      catch (Exception e) {
        _log.info("Persistence is not enabled. Certificates will not be persisted");
      }
    }

    bbAvailable = true;
    // now publish CA certificate
    publishCA();
  }

  private synchronized void publishCA() {
    CertificateCacheService cacheservice=(CertificateCacheService)
      _serviceBroker.getService(this,
			       CertificateCacheService.class,
			       null);

    if(cacheservice==null) {
      _log.warn("Unable to get Certificate cache Service in publishCAinLdap");
    }
    KeyRingService keyRing = (KeyRingService)
      _serviceBroker.getService(this, KeyRingService.class, null);
    if (keyRing == null) {
      _log.warn("KeyRing service not available yet, cannot update naming with CA cert.");
      return;
    }
    Certificate c=null;
    List certList = null;
    Enumeration enum=null;
    if(cacheservice!=null) {
      enum=cacheservice.getAliasList();
    }
    if(enum==null) {
      _log.warn("Alias list is null in Key management publishCAinLdap:");
    }
    if(enum!=null) {
      for(;enum.hasMoreElements();) {
        String a = (String)enum.nextElement();
        String cn = cacheservice.getCommonName(a);
        if(cn!=null) {
          _log.debug("Got common name for alias :"+ a + cn);
        }
        certList = keyRing.findCert(cn);
        // is there any valid certificate here?
        if (certList == null || certList.size() == 0){
          _log.debug(" Could not find cert in key ring for ca :"+cn);
          continue;
        }
        // is it a CA certificate? (not node, server, agent ...)
        c=((CertificateStatus)certList.get(0)).getCertificate();
        if (((CertificateStatus)certList.get(0)).getCertificateType()
            != CertificateType.CERT_TYPE_CA){
          _log.debug(" Certificate is not ca Type  :"+cn);
          continue;
        }
        _log.debug("got common name from alias : " + a
                  + " cn = " + cn);
         
        /*
          This is no longer required as we will not go to LDAP to get CA Cert

          List ldapList = keyRing.findCert(cn, KeyRingService.LOOKUP_LDAP);
          Certificate ldapcert = null;
          if (ldapList != null && ldapList.size() > 0)
          ldapcert = ((CertificateStatus)certList.get(0)).getCertificate();
          if(ldapcert==null) {
          log.debug("Found no certificate in LDAP for --> "
          + cn);
          }
          else {
          log.debug("found CA cert in ldap for :"
          + cn
          + " going to try next from ca keyStore");
          continue;
          }
        */

        // need to update CA to naming
        List bbEntryList = findCertByDistinguishedName(
          ((X509Certificate)c).getSubjectDN().getName());
          
        if (bbEntryList == null || bbEntryList.isEmpty()) {
          _log.warn("CA cert found in keystore but not in Blackboard!");
          continue;
        }
        CACertificateEntry certEntry = (CACertificateEntry)
          bbEntryList.get(0);
        publishCA(certEntry);
      }
    }
    else {
      _log.debug(" CA key store is empty ::");
    }
    _serviceBroker.releaseService(this,
                                 CertificateCacheService.class,
                                 cacheservice); 
     _serviceBroker.releaseService(this,
                                  KeyRingService.class,
                                  keyRing);
  }

  private void publishCA(CACertificateEntry certEntry) {
    KeyRingService keyRing = (KeyRingService)
      _serviceBroker.getService(this, KeyRingService.class, null);
    if (keyRing == null) {
      _log.warn("KeyRing service not available yet, cannot update naming with CA cert.");
      return;
    }
    try {
      X500Name dname = new X500Name(
        certEntry.getCertificate().getSubjectDN().getName());
      List pkc = keyRing.findPrivateKey(dname);
      if (pkc == null || pkc.isEmpty()) {
        _log.warn("Cannot publish a CA cert without a private key." + dname);
      }
      keyRing.updateNS(certEntry);
    }
    catch (Exception e) {
      if (_log.isWarnEnabled()) {
        if (!(e instanceof NameAlreadyBoundException)){
          _log.warn("Unable to publish CA certificate to LDAP: ", e);
        }
      }
    }
    _serviceBroker.releaseService(this,
                                  KeyRingService.class,
                                  keyRing);
  }

  /** Service listener for the Blackboard Service.
   *  Set the blackboard service when it becomes available.
   */
  private class BlackboardServiceAvailableListener implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      if(org.cougaar.core.service.BlackboardService.class.isAssignableFrom(sc)) {
	  _log.debug("BB Service is now available");
	if(_blackboardService==null){
	  setBlackboardService();
	}
      }
    }
  }

  private class CertificateBlackboardStorePredicate implements UnaryPredicate {
    public boolean execute(Object o) {
      boolean ret = false;
      if (o instanceof CertificateBlackboardStore) {
      //if (o instanceof Hashtable) {
	return true;
      }
      return ret;
    }
  }

  /*
  private class CertificateBlackboardStore extends Hashtable implements Serializable {
  }
  */


  /** ********************************************************************
   *  BlackboardClient implementation
   */

  // odd BlackboardClient method:
  public String getBlackboardClientName() {
    return "CACertDirectoryService";
  }

  // odd BlackboardClient method:
  public long currentTimeMillis() {
    throw new UnsupportedOperationException(
        this+" asked for the current time???");
  }

  // unused BlackboardClient method:
  public boolean triggerEvent(Object event) {
    // if we had Subscriptions we'd need to implement this.
    //
    // see "ComponentPlugin" for details.
    throw new UnsupportedOperationException(
        this+" only supports Blackboard queries, but received "+
        "a \"trigger\" event: "+event);
  }

}
