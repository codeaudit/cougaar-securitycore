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
import java.security.cert.*;
import java.security.Principal;
import java.security.PrivateKey;
import java.math.BigInteger;
import sun.security.x509.*;

// Cougaar core services
import org.cougaar.core.service.LoggingService;

// Cougaar security services
import org.cougaar.core.security.ssl.KeyRingSSLFactory;

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

public class CertificateCache
{
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

  /** A hashtable that contains a cache of all currently valid certificates.
   *  The hashtable key is a Principal.
   *  The hashtable value is a List of CertificateStatus
   */
  //private Hashtable certsCacheValid = new Hashtable(50);

  /** A hashtable that contains a cache of all currently valid private keys.
   *  The hashtable key is a Principal.
   *  The hashtable value is a List of PrivateKeyCert (which contains CertificateStatus and PrivateKey)
   */
  //private Hashtable privateKeyCacheValid = new Hashtable(50);

  private Hashtable bigint2dn=new Hashtable(50);
  //private boolean debug = false;

  /** How long do we wait before retrying to send a certificate signing
   * request to a certificate authority? */
  //private long pkcs10MinInterval = 10;

  /** A cross-reference to the directory key store. Used to make PKCS#10
   * requests to the CA as needed. */
  private DirectoryKeyStore directorykeystore = null;
  private LoggingService log;

  /** Cache to store strings containing revoked certificate DN, issuer DN, and serial number,
   * The certificate being revoked may not be in cert cache.
   */
  private Hashtable revokedCache = new Hashtable();

  public CertificateCache(DirectoryKeyStore d, LoggingService aLog)
  {
    directorykeystore = d;
    log = aLog;
  }

  /** Return the most up-to-date certificates for a given distinguished name.
   * Since there might be multiple certificates to choose from, the
   * certificate is selected by applying the following rules:
   * 1) Remove certificates that have been revoked.
   * 2) Remove certificates that have a "notBefore" date in the future.
   * 3) Remove certificates that have expired ("notAfter" date is in the past).
   * 4) From the remaining list, order by "notBefore" dates (most recent first),
   *    then by "notAfter" dates (longest time-to-live first).
   * We return the certificate that has been issued the most recently and
   * that has the longest time to live.
   *
   * TODO: handle gateway agents that talk to different realms, e.g.:
   * X wants to talk to A and B. A has been signed by CA1, B has been signed by CA2,
   * CA1 and CA2 do not have a common root CA.
   */

  /** Returns a List of valid certificates.
   * The certificates:
   * 1) have not been revoked.
   * 2) have a "notBefore" date in the past.
   * 3) have not expired
   */

  /**
   * NOTE: The certificates returned are valid but may NOT be trusted
   *  because the whole chain is not checked
   */
  public List getValidCertificates(X500Name x500Name)
  {
    List allCertificates = getCertificates(x500Name);
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
	aCertEntry.setCertificateTrust( CertificateTrust. CERT_TRUST_REVOKED_CERT);
	aCertEntry.setValidity(false);

	// Give the opportunity to invalidate existing or future sessions that
	// currently use this certificate.
	invalidateSessions(c1);

	log.debug("revoked status in cache:");
	X500Name subjectname=null;
	try {
	  subjectname= new X500Name(subjectDN);
	}
	catch(IOException ioexp) {
	  ioexp.printStackTrace();
	}
	certsCache.put(subjectname.getName(),list);
	log.debug("revoked status in cache:" + subjectDN);
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
    Enumeration allcerts = certsCache.elements();
    while (allcerts.hasMoreElements()) {
      List certList = (List)allcerts.nextElement();
      it = certList.listIterator();
      while (it.hasNext()) {
        CertificateStatus cs = (CertificateStatus)it.next();
        if (cs.isValid()) {
          checkCertificate(cs, true, true);
        }
      }
    }
  }

  /** Provide the opportunity to invalidate existing or future sessions that use a given certificate.
   */
  private void invalidateSessions(X509Certificate cert) {
    KeyRingSSLFactory.invalidateSession(cert);
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
              cs.setValidity(false);
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

  private CertificateStatus addCertStatus(List list, CertificateStatus certEntry,
					  PrivateKey privkey)
    throws SecurityException
  {
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
  public CertificateStatus addCertificate(CertificateStatus certEntry)
  {
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
    }
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

  /**
   * NOTE: The certificates returned are valid but may NOT be trusted
   *  because the whole chain is not checked
   */
  public List getValidPrivateKeys(X500Name x500Name) {
    List allCertificates = getPrivateKeys(x500Name);
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

  private List getPrivateKeys(String distinguishedName)
  {
    List list = (List) privateKeyCache.get(distinguishedName);
    return list;
  }

  /** Return all the private keys associated with a given distinguished name */
  public List getPrivateKeys(X500Name x500Name)
  {
    return getPrivateKeys(x500Name.getName());
  }


  /** Add a private key to the cache */
  public void addPrivateKey(PrivateKey privatekey, CertificateStatus certEntry)
  {
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

  public void printbigIntCache()
  {
    Enumeration e=bigint2dn.keys();
    CRLKey keys=null ;
    String dnname=null;
    log.debug("Printing contents of bigint 2dn mapping in certcache");
    while(e.hasMoreElements()) {
      keys=(CRLKey)e.nextElement();
      log.debug("In bigint cache  Key is :"
		+keys.toString() +" hash code is :"+keys.hashCode());
      dnname=(String)bigint2dn.get(keys);
      log.debug("In bigint cache dn name is :: "+dnname);
    }
  }
  public void printCertificateCache()
  {
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
  public String getDN(CRLKey crlkey)
  {
    if(log.isDebugEnabled())
    log.debug("Going to find dn for key :"+crlkey.toString());
    String subjectDN=null;
    if(bigint2dn.containsKey(crlkey)) {
      subjectDN=(String)bigint2dn.get(crlkey);
    }
    return subjectDN;

  }

  public Enumeration getKeysInCache()
  {
    return certsCache.keys();
  }

  private boolean checkCertificate(CertificateStatus cs) {
    return checkCertificate(cs, false, false);
  }

  /** Check the certificate validity of a certificate.
   */
  private boolean checkCertificate(CertificateStatus cs,
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
        directorykeystore.checkCertificateTrust(cs.getCertificate());
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
}
