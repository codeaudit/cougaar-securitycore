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
import java.security.cert.*;
import java.security.Principal;
import java.security.PrivateKey;

import sun.security.x509.*;


/** A hash table to store certificates from keystore, caKeystore and the LDAP directory
 * service, indexed by distinguished name.
 * Each entry in the hash table contains a list of all the certificates for a given
 * distinguished name.
 * The most up-to-date certificate is always the first element of the list. The list
 * is maintained by applying the following rules (from the end of the list):
 * 1) Revoked certificates are pushed to the very end of the list.
 * 2) Expired certificates are next.
 * 3) Certificates which are not yet valid are next.
 * 4) For remaining certificates, certificates are sorted by most recently issued
 *    certificate first.
 */

public class CertificateCache
{
  private Hashtable certsCache = new Hashtable(50);
  private Hashtable privateKeyCache = new Hashtable(50);

  private Hashtable cn2dn = new Hashtable(50);
  private boolean debug = false;


  /** A cross-reference to the directory key store. Used to make PKCS#10
   * requests to the CA as needed. */
  private DirectoryKeyStore directorykeystore = null;

  public CertificateCache(DirectoryKeyStore d)
  {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    directorykeystore = d;
  }

  /** Return the most up-to-date certificate for a given distinguished name.
   * Since there might be multiple certificates to choose from, the certificate is
   * selected by applying the following rules:
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
  public CertificateStatus getCertificate(String distinguishedName)
  {
    X500Name x500Name = null;
    try {
      x500Name = new X500Name(distinguishedName);
    } catch(Exception e) {
      if (debug) {
	System.out.println("Unable to get Common Name - " + e);
      }
    }
    return getCertificate(x500Name);
  }

  public CertificateStatus getCertificate(X500Name x500Name)
  {
    CertificateStatus reply = null;

    if (debug) {
      System.out.println("CertificateCache. getCert(" + x500Name + ")");
    }
    if (x500Name == null) {
      return null;
    }

    // The most up-to-date certificate should be the first in the list.
    ArrayList v = getCertificates(x500Name);
    if (v == null) {
      return null;
    }
    Iterator it = v.listIterator();
    while (it.hasNext()) {
      // The first element in the list should be the most up-to-date
      // certificate. However, there are some cases where it may not.
      // For instance, we may have just received a new certificate from the CA,
      // but it is not yet valid and we still have another certificate
      // which is still valid.
      CertificateStatus cs = (CertificateStatus) it.next();
      if (cs == null) {
	continue;
      }
      try {
	cs.checkCertificateValidity();
	reply = cs;
	// Certificate is valid. Return it.
	break;
      }
      catch (CertificateNotTrustedException e) {
	// Find out cause
	if (e.cause == CertificateTrust.CERT_TRUST_SELF_SIGNED) {
	  /* Certificate has not been signed by a CA. Either the CA has refused
	   * to issue the certificate or communication with the CA was not
	   * possible. */
	  if (debug) {
	    System.out.println("Certificate is not signed by a trusted CA");
	  }
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
	  if (getPrivateKey(x500Name) != null) {
	    // This is a local entity
	    // Send a PKCS#10 request to the CA.
	    try {
	      directorykeystore.addKeyPair(x500Name.getCommonName(),
					   cs.getCertificateAlias());
	    }
	    catch (Exception exp) {
	      // Unable to send request. Give up.
	    }
	  }
	}
	else if (e.cause == CertificateTrust.CERT_TRUST_UNKNOWN) {
	  // Try to find out certificate trust
	  if (debug) {
	    System.out.println("Certificate trust is unknown");
	  }
	}
	else {
	  // Otherwise, certificate is not trusted.
	}
	// TODO: mechanism by which one can send a message to a remote entity
	// requesting for that entity to generate a certificate that we can use.
      }
      catch (CertificateException e) {
	// There is no suitable private key (expired, revoked, ...)
	// Request a new one to the Certificate Authority
	if (debug) {
	  System.out.println("Invalid certificate: " + e);
	}
      }
    }
    return reply;
  }

  /** TODO: Establish clear naming conventions for the Cougaar system */
  public CertificateStatus getCertificateByCommonName(String commonName) {
    // Create a distinguished name from the Common Name.
    String dname = (String) cn2dn.get(commonName);
    if (dname == null) {
      return null;
    }
    else {
      return getCertificate(dname);
    }
  }

  /** Return an ArrayList of certificates which:
   * 1) have not been revoked.
   * 2) have a "notBefore" date in the past.
   * 3) have not expired
   */
  public ArrayList getValidCertificates(String distinguishedName)
  {
    ArrayList v = getCertificates(distinguishedName);
    // Get the current date
    Date now = new Date();

    ArrayList validCerts = new ArrayList();

    ListIterator it = v.listIterator();
    while (it.hasNext()) {
      CertificateStatus cs = (CertificateStatus) it.next();
      if (cs.isValid() == true) {
	// Certificate has not been revoked (as far as we know)
	X509Certificate c = (X509Certificate) cs.getCertificate();
	Date notBefore = c.getNotBefore();
	Date notAfter = c.getNotAfter();
	if (notBefore.before(now) && notAfter.after(now)) {
	  // Certificate can be used now ("not before" date is not in the future)
	  // Certificate has not expired ("not after" date is not in the past)
	  validCerts.add(cs);
	}
      }
    }
    return validCerts;
  }

  public ArrayList getCertificates(String distinguishedName)
  {
    X500Name x500Name = null;
    try {
      x500Name = new X500Name(distinguishedName);
    } catch(Exception e) {
      System.out.println("Unable to get Common Name - " + e);
    }
    return getCertificates(x500Name);
  }

  /** Return all the certificates associated with a given distinguished name */
  public ArrayList getCertificates(X500Name x500Name)
  {
    ArrayList list = (ArrayList) certsCache.get(x500Name);
    return list;
  }

  /** Change certificate status in the certificate cache */
  public void revokeCertificate(Certificate certificate)
  {
  }

  private void addCertStatus(ArrayList list, CertificateStatus certEntry,
			     PrivateKey privkey)
    throws SecurityException
  {
    if(certEntry != null) {
      X509Certificate cert = (X509Certificate) certEntry.getCertificate();
      // Retrieve the distinguished name, which is used as a key in
      // the certificate cache.
      Principal principal = cert.getSubjectDN();

      // Are there existing certificates for this principal?
      // If yes, add the new certificate to the ArrayList. Otherwise, create a
      // new entry in the hash table.
      PrivateKeyCert pcert = null;

      if (privkey != null) {
	pcert = new PrivateKeyCert(privkey, certEntry);
	if (debug) {
	  System.out.println("add Private Key:" + principal);
	}
      }
      else {
	if (debug) {
	  System.out.println("add Certificate:" + principal);
	}
      }
      if (debug) {
	System.out.print("Alias: " + certEntry.getCertificateAlias()
			 + ". Trust:" + certEntry.getCertificateTrust()
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
	if (debug) {
	  System.out.println(" (first certificate)");
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
	    if (aCertEntry.getCertificateType() != certEntry.getCertificateType()
		|| aCertEntry.getCertificateOrigin() != certEntry.getCertificateOrigin()) {
	      // Error. Certificate type and Certificate Origin cannot change
	      if (debug) {
		System.out.println("Error. Trying to update immutable fields: ");
		System.out.println("   " + aCertEntry.getCertificateType() + " ==> " 
				   + certEntry.getCertificateType());
		System.out.println("   " + aCertEntry.getCertificateOrigin() + " ==> "
				   + certEntry.getCertificateOrigin());
	      }
	      throw new SecurityException("Error. Trying to update immutable fields");
	    }
	    if (debug) {
	      System.out.println("\nUpdating certificate status. Old trust:"
				 + aCertEntry.getCertificateTrust()
				 + " - new trust:" 
				 + certEntry.getCertificateTrust());
	    }
	    // Update trust.
	    aCertEntry.setCertificateTrust(certEntry.getCertificateTrust());

	    // Update certificate (the signature may have changed)
	    aCertEntry.setCertificate(certEntry.getCertificate());
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
	      if (debug) {
		System.out.println(" (insert before index=" + it.nextIndex() + " - size="
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
	    if (debug) {
	      System.out.println(" (insert at list end. List size=" + list.size() + ")");
	    }
	  }
	}
      }
    }
  }

  /** Add a certificate to the cache */
  public void addCertificate(CertificateStatus certEntry)
  {
    if(certEntry != null) {
      X509Certificate cert = (X509Certificate) certEntry.getCertificate();
      // Retrieve the distinguished name, which is used as a key in
      // the certificate cache.
      Principal principal = cert.getSubjectDN();

      try {
	// Update Common Name to DN hashtable
	updateCn2Dn(principal);
      }
      catch (CertificateException e) {
	System.out.println("Configuration Error:");
	System.out.println(e.getMessage());
	return;
      }

      ArrayList list = (ArrayList)certsCache.get(principal);
      if (list == null) {
	list = new ArrayList();
      }

      addCertStatus(list, certEntry, null);
      certsCache.put(principal, list);
    }
  }

  public PrivateKey getPrivateKey(String distinguishedName)
  {
    X500Name x500Name = null;
    if (distinguishedName == null) {
      return null;
    }
    try {
      x500Name = new X500Name(distinguishedName);
    } catch(Exception e) {
      if (debug) {
	System.out.println("Unable to get Common Name - " + e);
      }
    }
    return getPrivateKey(x500Name);
  }

  public PrivateKey getPrivateKey(X500Name x500Name)
  {
    PrivateKey privkey = null;
    if (debug) {
      System.out.println("CertificateCache. getPrivateKey(" + x500Name + ")");
    }

    if (x500Name == null) {
      return null;
    }
    // The most up-to-date certificate should be the first in the list.
    ArrayList v = getPrivateKeys(x500Name);
    if (v == null) {
      return null;
    }

    Iterator it = v.listIterator();
    while (it.hasNext()) {
      // The first element in the list should be the most up-to-date
      // certificate. However, there are some cases where it may not.
      // For instance, we may have just received a new certificate from the CA,
      // but it is not yet valid and we still have another certificate
      // which is still valid.

      PrivateKeyCert pcert = (PrivateKeyCert) it.next();
      if (pcert == null) {
	continue;
      }
      try {
	pcert.getCertificateStatus().checkCertificateValidity();
	privkey = pcert.getPrivateKey();
	// Key is valid. Return it.
	break;
      } catch (CertificateNotTrustedException e) {
	// Find out cause
	if (e.cause == CertificateTrust.CERT_TRUST_SELF_SIGNED) {
	  /* Certificate has not been signed by a CA. Either the CA has refused
	   * to issue the certificate or communication with the CA was not
	   * possible. */
	  if (debug) {
	    System.out.println("Certificate is not signed by a trusted CA");
	  }
	  // Send a PKCS#10 request to the CA.
	  try {
	    directorykeystore.addKeyPair(x500Name.getCommonName(),
					 pcert.getCertificateStatus().getCertificateAlias());
	  }
	  catch (Exception exp) {
	    // Unable to send request. Give up.
	  }
	}
	else if (e.cause == CertificateTrust.CERT_TRUST_UNKNOWN) {
	  // Try to find out certificate trust
	  if (debug) {
	    System.out.println("Certificate trust is unknown");
	  }
	}
	else {
	  // Otherwise, certificate is not trusted.
	  // Request a new certificate to the Certificate Authority?
	}
      }
      catch (CertificateException e) {
	// There is no suitable private key (expired, revoked, ...)
	// Request a new one to the Certificate Authority
	if (debug) {
	  System.out.println("Invalid certificate: " + e);
	}
      }
    }
    return privkey;
  }

  /** TODO: Establish clear naming conventions for the Cougaar system */
  public PrivateKey getPrivateKeyByCommonName(String commonName)
  {
    // Create a distinguished name from the Common Name.
    String dname = (String) cn2dn.get(commonName);
    if (debug) {
      System.out.println("getPrivateKeyByCommonName: cn=" + commonName
			 + " - dn=" + dname);
    }
    return getPrivateKey(dname);
  }


  public ArrayList getPrivateKeys(String distinguishedName)
  {
    X500Name x500Name = null;
    try {
      x500Name = new X500Name(distinguishedName);
    } catch(Exception e) {
      System.out.println("Unable to get Common Name - " + e);
    }
    return getPrivateKeys(x500Name);
  }

  /** Return all the private keys associated with a given distinguished name */
  public ArrayList getPrivateKeys(X500Name x500Name)
  {
    ArrayList list = (ArrayList) privateKeyCache.get(x500Name);
    return list;
  }


  /** Add a private key to the cache */
  public void addPrivateKey(PrivateKey privatekey, CertificateStatus certEntry)
  {
    X509Certificate cert = (X509Certificate) certEntry.getCertificate();
    // Retrieve the distinguished name, which is used as a key in
    // the certificate cache.
    Principal principal = cert.getSubjectDN();

    try {
      // Update Common Name to DN hashtable
      updateCn2Dn(principal);
    }
    catch (CertificateException e) {
      System.out.println("Configuration Error: " + e);
      return;
    }

    // Are there existing private keys for this principal?
    // If yes, add the new private key to the ArrayList. Otherwise, create a
    // new entry in the hash table.
    ArrayList list = (ArrayList)privateKeyCache.get(principal);
    if (list == null) {
      list = new ArrayList();
    }

    addCertStatus(list, certEntry, privatekey);

    privateKeyCache.put(principal, list);
  }

  private void updateCn2Dn(Principal principal)
    throws CertificateException
  {
    X500Name x500Name;
    String cn = null;
    try {
      x500Name = new X500Name(principal.getName());
      cn = x500Name.getCommonName();
    } catch(Exception e) {
      if (debug) {
	System.out.println("Unable to get Common Name - " + e);
      }
    }
    /* Since the common name must currently be unique, it is a configuration error
     * if two distinguished names have the same common name. */
    String aName = (String)cn2dn.get(cn);
    if (aName != null) {
      if (!aName.equals(principal.getName())) {
	// Cannot continue. Configuration error.
	throw new CertificateException("Two DNs have same CN. Keeping "
				       + aName + " - " + principal.getName() + " excluded");
      }
    }
    cn2dn.put(cn, principal.getName());
  }

  public void printCertificateCache()
  {
    // Certificates
    Enumeration e = certsCache.keys();
    System.out.println("============== Certificates:");
    while (e.hasMoreElements()) {
      X500Name name = (X500Name) e.nextElement();
      ArrayList list = (ArrayList) certsCache.get(name);
      ListIterator it = list.listIterator();
      System.out.println("Certificates for: " + name);
      while (it.hasNext()) {
	CertificateStatus cs = (CertificateStatus) it.next();
	System.out.println(cs);
      }
    }

    // Private keys
    e = privateKeyCache.keys();
    System.out.println("============== Private keys:");
    while (e.hasMoreElements()) {
      X500Name name = (X500Name) e.nextElement();
      ArrayList list = (ArrayList) privateKeyCache.get(name);
      ListIterator it = list.listIterator();
      System.out.println("PrivateKeys for: " + name);
      while (it.hasNext()) {
	PrivateKeyCert pcert = (PrivateKeyCert) it.next();
	System.out.println(pcert);
      }
    }
  }

  public Enumeration getKeysInCache()
  {
    return certsCache.keys();
  }

  private class PrivateKeyCert
  {
    public PrivateKey pk;
    public CertificateStatus cert;

    public PrivateKeyCert(PrivateKey p, CertificateStatus c)
    {
      pk = p;
      cert = c;
    }
    public CertificateStatus getCertificateStatus()
    {
      return cert;
    }
    public PrivateKey getPrivateKey()
    {
      return pk;
    }
    public String toString()
    {
      return cert.toString();
    }
  }
}
