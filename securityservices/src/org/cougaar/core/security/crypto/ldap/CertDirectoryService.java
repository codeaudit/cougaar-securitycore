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

package org.cougaar.core.security.crypto.ldap;

import java.util.*;
import java.io.*;
import java.lang.IllegalArgumentException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.MessageDigest;
import javax.naming.*;
import javax.naming.directory.*;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.crypto.Base64;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;
import org.cougaar.core.security.services.ldap.LdapEntry;
import org.cougaar.core.security.services.ldap.MultipleEntryException;
import org.cougaar.core.security.services.ldap.MaxConnectionRetryException;
import org.cougaar.core.security.services.util.ConfigParserService;

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
  public static final String CACERTIFICATE_ATTRIBUTE= "cACertificate;binary";
  public static final String USERCERTIFICATE_ATTRIBUTE ="userCertificate;binary";
  public static final String CERTIFICATEREVOCATIONLIST_ATTRIBUTE ="certificateRevocationList;binary";
  public static final String AUTHORITYREVOCATIONLIST_ATTRIBUTE ="authorityRevocationList;binary";
  public static final String OBJECTCLASS_CERTIFICATIONAUTHORITY ="certificationAuthority";
  public static final String OBJECTCLASS_INETORGPERSON ="inetOrgPerson";
  protected static final int MAX_RETRIES = 5;
  protected static final int RETRY_TIMEOUT = 100;

  protected String ldapServerUrl;
  /* protected DirContext context;
  protected DirContext initialContext;
  */
  protected boolean initializationOK = false;
  protected static String CONTEXT_FACTORY = 
    "com.sun.jndi.ldap.LdapCtxFactory";
  protected ServiceBroker serviceBroker;
  protected LoggingService log;
  /** The reason why the connection to the LDAP server was not successful */
  protected String rootCauseMsg;
  private boolean useSSL = false;

  //protected boolean log.isDebugEnabled() = false;

//protected String caDistinguishedName;
//private boolean connectionClosed = true;
//private Object connectionLock = new Object();
  protected  ContextHolder contextHolder;
  protected Object _contextLock = new Object();

  protected  class ContextHolder {
    /** Time after which LDAP connection is automatically closed. */
    private int _timeToSleep = 10 * 1000; 
    protected DirContext _context;
    private boolean _connectionClosed = true;
    private CloseConnectionTask _closeConnectionTask = new CloseConnectionTask();
    private Timer _timer = new Timer();
    private Hashtable _config;
 
    private class CloseConnectionTask extends TimerTask {
      public void run() {
	try {
	  synchronized(_contextLock) {
	    _context.close();  
	    _connectionClosed = true;
	  }
	}
	catch(Exception e) {
	  log.warn("Error occurred in ConnectionTimer" + e.getMessage());
	}
      }
    }

    public ContextHolder(Hashtable config) {
      _config = config;
    }

    public DirContext getContext()
      throws javax.naming.NamingException {
      synchronized(_contextLock) {
	if(_connectionClosed) {
	  _context = null;
	  String cause = null;
	  int i;
	  if (log.isDebugEnabled()) {
	    Enumeration enum = _config.keys();
	    log.debug("Connecting to LDAP using following parameters:");
	    while (enum.hasMoreElements()) {
	      String key = (String)enum.nextElement();
	      log.debug(key + "=" + _config.get(key));
	    }
	  }
	  for (i = 0 ; i < MAX_RETRIES ; i++) {
	    try {
	      _context = new InitialDirContext(_config);
	      log.debug("Created context");
	      break;
	    }
	    catch (javax.naming.NamingSecurityException e) {
	      log.warn("Unable to connect to LDAP: " + ldapServerUrl + ":" + e);
	      throw e;
	    }
	    catch (javax.naming.NameNotFoundException e) {
	      log.warn("Unable to connect to LDAP: " + ldapServerUrl + ":" + e);
	      throw e;
	    }
	    catch (javax.naming.NamingException e) {
	      log.info("Unable to connect to LDAP: " + ldapServerUrl + ". Will retry later in"
		       + RETRY_TIMEOUT + "ms");
	      cause = e.getMessage();
	      try {
		Thread.sleep(RETRY_TIMEOUT);
	      }
	      catch (InterruptedException exp) {
		log.error("Was interrupted while sleeping:" + exp);
		return null;
	      }
	    } // for()
	    if (_context == null) {
	      throw new MaxConnectionRetryException("Unable to connect to LDAP " + ldapServerUrl + " after "
						    + (i + 1) + " attempts. Cause:" + cause);
	    }

	    try {
	      _timer.schedule(_closeConnectionTask, _timeToSleep);
	    }
	    catch (Exception e) {
	      log.error("Unable to schedule close connection task:" + e);
	      return null;
	    }
	    _connectionClosed = false;
	  }
	} // if (_connectionClosed)
	return _context;
      }
    }
  }
  
  /** Creates new CertDirectoryService */
  public CertDirectoryService(CertDirectoryServiceRequestor requestor, ServiceBroker sb)
    throws javax.naming.NamingException
    {
      serviceBroker = sb;
      Hashtable env=null;
      log = (LoggingService)
	serviceBroker.getService(this,
				 LoggingService.class, null);

      ConfigParserService configParser = (ConfigParserService)
	serviceBroker.getService(this,
				 ConfigParserService.class, null);

      if(requestor == null) {
	throw new IllegalArgumentException("CertDirectoryServiceRequestor is null!");
      }
      String url = requestor.getCertDirectoryUrl();
      if (log.isDebugEnabled()) {
	log.debug("Creating Directory Service for " + url);
      }
      if (url != null) {
	// Create a subcontext in LDAP if it does not exist.
	int slash = url.lastIndexOf("/");
	if (configParser.isCertificateAuthority() && slash != -1) {
	  // try to create the directory structure:
	  String dn = null;
	  dn = url.substring(slash + 1);
	  String baseURL = url.substring(0, slash);
	  setDirectoryServiceURL(baseURL);
	  env=initDirectoryService(requestor.getCertDirectoryPrincipal(),
				   requestor.getCertDirectoryCredential()); 
	  contextHolder = new ContextHolder(env);
	  createDcObjects(dn);
	}
	// set the directory context to the right URL
	setDirectoryServiceURL(url);
	env=initDirectoryService(requestor.getCertDirectoryPrincipal(),
				 requestor.getCertDirectoryCredential());
	if(!env.isEmpty()){
	  contextHolder = new ContextHolder(env);
	  try {
            synchronized(_contextLock) {
	      DirContext context = contextHolder.getContext();
	      initializationOK=true;
            }
	  }
	  catch(NameNotFoundException nfe) {
	    if (log.isWarnEnabled()) {
	      log.warn("Couldn't connect to ldap: ", nfe);
	    }
	  }
	}
      }
      else {
	throw new
	  IllegalArgumentException("Directory Service URL not specified.");
      }
    }

  public String getDirectoryServiceURL() {
    return ldapServerUrl;
  }
    
  /**
   * Construct a URL to the LDAP certificate directory.
   * ldap://host:port/dccomponents
   * Example:
   *   ldap://pear:389/dc=csmart2, dc=cougaar, dc=org
   */
  protected void  setDirectoryServiceURL(String aURL) {
    int slash = aURL.lastIndexOf("/");
    //String dn = null;
    String bURL = aURL;

    /*
    if (slash != -1) {
      //dn   = aURL.substring(slash+1);
      bURL = aURL.substring(0,slash + 1);
    }
    */
    if (bURL.startsWith("ldaps://")) {
      useSSL = true;
      int colonIndex = bURL.indexOf(":",8);
      int slashIndex = bURL.indexOf("/",8);
      String host;
      if (slashIndex == -1) slashIndex = bURL.length();
      if (colonIndex == -1 || colonIndex > slashIndex) {
	String oldURL = bURL;
	// there is no default port -- change the default
	// port to 636 for ldaps
	if (slashIndex == 0) {
	  // there is no host either -- use 0.0.0.0 as host
	  host = "0.0.0.0";
	} else {
	  host = bURL.substring(8,slashIndex);
	}
	bURL = "ldap://" + host + ":636" + bURL.substring(slashIndex);
	if (log.isWarnEnabled()) {
	  log.warn("No default port has been set. original URL: " + oldURL + ". New URL: " + bURL);
	}
      } else {
	bURL = "ldap://" + bURL.substring(8);
      }
    }
    ldapServerUrl=bURL;
      
  }
    
  protected Hashtable  initDirectoryService(String principal, String credentials) {
    Hashtable env = new Hashtable();
    env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
    env.put(Context.PROVIDER_URL,ldapServerUrl);
    if (useSSL) {
      env.put(Context.SECURITY_PROTOCOL, "ssl");
      env.put("java.naming.ldap.factory.socket", 
	      "org.cougaar.core.security.ssl.KeyRingSSLFactory");
    }
    if((principal!=null)&&(credentials!=null)) {
      env.put(Context.SECURITY_PRINCIPAL, principal);
      env.put(Context.SECURITY_CREDENTIALS, credentials);
    }
    return env;
  }


  private void createDcObjects(String dn) 
    throws NamingException {
    if (dn == null) return;
    ArrayList names = new ArrayList();
    ArrayList vals  = new ArrayList();
    ArrayList dns   = new ArrayList();
    int commaIndex = -1;
    do {
      dns.add(dn.substring(commaIndex+1));
      int eqIndex = dn.indexOf("=", commaIndex);
      names.add(dn.substring(commaIndex+1, eqIndex));
      commaIndex = dn.indexOf(",", commaIndex+1);
      if (commaIndex == -1) {
	vals.add(dn.substring(eqIndex+1));
      } else {
	vals.add(dn.substring(eqIndex+1, commaIndex));
      }
    } while (commaIndex != -1);
   
    int firstAvailable = -1;
    
    synchronized(_contextLock) {
      DirContext context = null;
      try {
	context = contextHolder.getContext();
      }
      catch (NamingException e) {
	log.warn("Unable to create the LDAP subcontext for " + dn + ". Reason: " + e);
	throw e;
      }
      for (int i = 0; i < dns.size() && firstAvailable == -1; i++) {
	try {
	  // check if the object exists:
       
	  Attributes attrs =null;
	  attrs= context.getAttributes((String) dns.get(i));
	  if (attrs != null) {
	    firstAvailable = i;
	  }
	} catch (NamingException e) {
	  // doesn't exist
	  log.warn("Unable to get the DNS attributes:" + e);
	}
      }
   
      if (firstAvailable == -1) {
	firstAvailable = dns.size();
      }
   
      for (int i = firstAvailable - 1; i >= 0; i--) {
	if (log.isInfoEnabled()) {
	  log.info("CA dn " + dns.get(i) + 
		   " does not exist. Creating...");
	}
	BasicAttributes ba = new BasicAttributes();
	Attribute objClass = new BasicAttribute("objectClass","dcObject");
	objClass.add("organization");
	ba.put(objClass);
     
	String name = (String) names.get(i);
	String val  = (String) vals.get(i);
	ba.put(name,val);
	ba.put("o", "UltraLog");
	ba.put("description", "Certificates");
	try {
	  context.createSubcontext((String) dns.get(i), ba);
	}
	catch (NamingException e) {
	  if (log.isWarnEnabled()) {
	    log.warn("Could not create dn " + dns.get(i));
	  }
	}
      }
    }
  }
 
/*
   for (int i = 0 ; i < MAX_RETRIES ; i++) {
      try {
	Hashtable env = new Hashtable();
	env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
	env.put(Context.PROVIDER_URL, ldapServerUrl);
	if (useSSL) {
	  env.put(Context.SECURITY_PROTOCOL, "ssl");
	  env.put("java.naming.ldap.factory.socket", 
		  "org.cougaar.core.security.ssl.KeyRingSSLFactory");
	}
      
	context=new InitialDirContext(env);

	initialContext = context;
	initializationOK = true;
	break;
      }
      catch(NamingException nexp) {
	rootCauseMsg = "Unable to connect to LDAP server: "
	  + ldapServerUrl
	  + ". Reason: " + nexp + ". Using local keystore only.";
	if (log.isWarnEnabled()) {
	  log.warn(rootCauseMsg, nexp);
	}
      }
    }
  }
*/
 

  /** Return all the certificates that have a given common name.
   * It is up to the caller to verify the validity of the certificate. */
  public LdapEntry[] searchByCommonName(String commonName) {
    String filter = "(cn=" + commonName + ")";
    return searchWithFilter(filter);
  }

  public synchronized LdapEntry[] searchWithFilter(String filter)
    {
      if(log.isDebugEnabled()) {
	log.debug("Search with filter called & filter is "+filter);
      }
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
	if (log.isDebugEnabled()) {
	  log.debug("Certificate status: "
		    + ldapEntry.getStatus()
		    + " - uid: " + ldapEntry.getUniqueIdentifier());
	}
	certList.add(ldapEntry);
      }
      return (LdapEntry[]) certList.toArray(certs);
    }


  public NamingEnumeration internalSearchWithFilter(String filter)
    {
      if (!isInitialized()) {
	if(log.isDebugEnabled())
	  log.debug(" Ldap is not init");
	return null;
      }
      NamingEnumeration results=null;
      SearchControls constraints=new SearchControls();
      constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
      if (log.isDebugEnabled()) {
	log.debug("Filter provided for search:" + filter);
	log.debug("LDAP server url:" + ldapServerUrl);
      }
      synchronized(_contextLock) {
	DirContext context = null;
	try {
	  context = contextHolder.getContext();
	}
	catch (NamingException e) {
	  log.warn("Unable to lookup in LDAP:" + filter + ". Reason: " + e);
	  return null;
	}
	try {
	  if (context != null) {
	    results=context.search(ldapServerUrl, filter, constraints);
	  }
	}
	catch(Exception exp) {
	  if (log.isInfoEnabled()) {
	    log.info("Search failed for filter:" + filter + ". Ldap URL:" +
		     ldapServerUrl + ". Reason: " + exp);
	  }
	}
      }
      if(log.isDebugEnabled()) {
	log.debug("returning results for filter :"+filter);
      }
      return results;
    } 

  /** Should be implemented by a class specialized for a particular
   *  Certificate Directory Service. */
  public abstract LdapEntry getCertificate(SearchResult result);

  private boolean isInitialized() {
    if (log.isDebugEnabled() && !initializationOK) {
      log.debug("LDAP client not initialized");
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
      if(log.isDebugEnabled()) {
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
      if(log.isDebugEnabled())ex.printStackTrace();
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
      if(log.isDebugEnabled())ex.printStackTrace();
    }
    return cert;
  }

  /** Dump the LDAP context.
   */
  public void dumpContexts() {
    try {
      synchronized(_contextLock) {
	DirContext context = contextHolder.getContext();
	String name = null;
	name=context.getNameInNamespace();
	log.debug("Directory (" + name + ") contains:");
	NamingEnumeration list = context.list("");
      
	//NamingEnumeration list1 = initialContext.search("", null);

	while (list.hasMore()) {
	  NameClassPair nc = (NameClassPair)list.next();
	  log.debug(nc.toString());
	}
      }
    }
    catch (Exception e) {
      log.debug("Exception: " + e);
    }
  }

  public String toString() {
    return "LdapURL: " + ldapServerUrl;
  }
}
