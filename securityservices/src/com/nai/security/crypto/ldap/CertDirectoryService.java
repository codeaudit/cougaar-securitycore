/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */

package com.nai.security.crypto.ldap;

import java.util.*;
import java.io.*;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.MessageDigest;
import javax.naming.*;
import javax.naming.directory.*;

import com.nai.security.crypto.Base64;

/** RFCs that are applicable to LDAP:
 *  - RFC 2256: A summary of X.500 user schema for LDAPv3
 *              Defines acceptable attributes for DNs
 *  - RFC 1779: A string representation of distinguished names
 *  - RFC 2253: UTF-8 string representation of distinguished names
 *  - RFC 1274: 
 */
public abstract class CertDirectoryService
{
  public static final String UID_ATTRIBUTE = "uniqueIdentifier";
  public static final String DN_ATTRIBUTE = "DN";
  public static final String STATUS_ATTRIBUTE = "info";

  protected String ldapServerUrl;
  protected DirContext context;
  protected boolean initializationOK = false;
  protected static String CONTEXT_FACTORY = 
    "com.sun.jndi.ldap.LdapCtxFactory";

  protected boolean debug = false;

  /** Creates new CertDirectoryService */

  public CertDirectoryService(String aURL) 
    throws Exception
  {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    if (debug) {
      System.out.println("Creating Directory Service for " + aURL);
    }
    if (aURL != null) {
      setDirectoryServiceURL(aURL);
    }
    else {
      throw new Exception("Directory Service URL not specified.");
    }
  }

  public void setDirectoryServiceURL(String aURL)
  {
    ldapServerUrl = aURL;
    initializationOK = false;
    if (debug) {
      System.out.println("Using LDAP certificate directory: "
			 + ldapServerUrl);
    }

    try {
      Hashtable env = new Hashtable();
      env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
      env.put(Context.PROVIDER_URL, ldapServerUrl);
      
      context=new InitialDirContext(env);
      initializationOK = true;
    }
    catch(NamingException nexp) {
      if (debug) {
	System.err.println("Warning:can't connect to LDAP server: "
			   + ldapServerUrl);
	System.err.println("Reason: " + nexp + ". Use local keystore only.");
	nexp.printStackTrace();
      }
    }
  }

  /** Return all the certificates that have a given common name.
   * It is up to the caller to verify the validity of the certificate. */
  public LdapEntry[] searchByCommonName(String commonName) {
    String filter = "(cn=" + commonName + ")";
    return searchWithFilter(filter);
  }

  public LdapEntry[] searchWithFilter(String filter)
  {
    NamingEnumeration search_results = internalSearchWithFilter(filter);
    ArrayList certList = new ArrayList();
    LdapEntry[] certs = new LdapEntry[0];

    while((search_results!=null) && (search_results.hasMoreElements())) {
      SearchResult result = null;
      try {
	result = (SearchResult)search_results.next();
      }
      catch (NamingException e) {
	continue;
      }
      LdapEntry ldapEntry = null;

      // Retrieve the certificate.
      ldapEntry = getCertificate(result);

      if (ldapEntry == null) {
	continue;
      }
      if (debug) {
	System.out.println("Certificate status: "
			   + ldapEntry.getStatus()
			   + " - uid: " + ldapEntry.getUniqueIdentifier());
      }
      certList.add(ldapEntry);
    }
    return (LdapEntry[]) certList.toArray(certs);
  }


  private NamingEnumeration internalSearchWithFilter(String filter)
  {
    if (!isInitialized()) {
      return null;
    }
    NamingEnumeration results=null;
    SearchControls constraints=new SearchControls();
    constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
    if (debug) {
      System.out.println("Filter provided for search:" + filter);
      System.out.println("LDAP server url:" + ldapServerUrl);
    }
    try {
      if (context != null) {
	results=context.search(ldapServerUrl, filter, constraints);
      }
    }
    catch(NamingException searchexp) {
      System.out.println("search failed");
      searchexp.printStackTrace();
    }
    return results;
  }

  /** Should be implemented by a class specialized for a particular
   *  Certificate Directory Service. */
  public abstract LdapEntry getCertificate(SearchResult result);

  private boolean isInitialized() {
    if (debug && !initializationOK) {
      System.out.println("LDAP client not initialized");
    }
    return initializationOK;
  }
    
  protected String toHex(byte[] data) {
    StringBuffer buff = new StringBuffer();
    for(int i = 0; i < data.length; i++) {
      String digit = Integer.toHexString(data[i] & 0x00ff);
      if(digit.length() < 2)buff.append("0");
      buff.append(digit);
    }
    return buff.toString();
  }

  protected String getDigestAlgorithm(X509Certificate cert) {
    String digestAlg = cert.getSigAlgName().substring(0,3);
    return digestAlg;
  }

  protected String getHashValue(X509Certificate cert) {
    MessageDigest certDigest;
    byte[] der = null;
    String hash = null;

    // Use the prefix of the signature algorithm for creating a DN
    // Acceptable values: SHA, MD2, MD4, MD5
    try { 
      certDigest = MessageDigest.getInstance(getDigestAlgorithm(cert));
      der = cert.getTBSCertificate();
      certDigest.reset();
      certDigest.update(der);
      hash = toHex(certDigest.digest());
    }
    catch(Exception ex) {
      if(debug) {
	ex.printStackTrace();
      }
    }
    return hash;
  }

  public X509Certificate getCertificateInstance(String pem) {
    X509Certificate cert = null;

    try {
      InputStream inStream = 
	new ByteArrayInputStream(Base64.decode(pem.toCharArray()));
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      cert = (X509Certificate)cf.generateCertificate(inStream);
      inStream.close();
    }
    catch(Exception ex) {
      if(debug)ex.printStackTrace();
    }
    return cert;
  }

  public X509Certificate loadCert(String fileName) {
    X509Certificate cert = null;
    try {
      InputStream inStream = new FileInputStream(fileName);
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      cert = (X509Certificate)cf.generateCertificate(inStream);
      inStream.close();
    }
    catch(Exception ex) {
      if(debug)ex.printStackTrace();
    }
    return cert;
  }


}
