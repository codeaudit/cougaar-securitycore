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


package org.cougaar.core.security.crypto.ldap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchResult;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertificateRevocationStatus;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceCA;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;
import org.cougaar.core.security.services.ldap.MultipleEntryException;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.util.CrlUtility;

public class OpenLdapCertDirectoryServiceImpl
extends CertDirectoryService
implements CertDirectoryServiceClient, CertDirectoryServiceCA
{
 
  public static final String revoked="3";

  private ConfigParserService configParser;

  public OpenLdapCertDirectoryServiceImpl(CertDirectoryServiceRequestor requestor, ServiceBroker sb)
    throws javax.naming.NamingException {
    super(requestor, sb);
  }

  private static String[] breakURL(String url) {
    int index = url.lastIndexOf("/");
    String component;
    if (index == -1) {
      component = "";
    } else {
      component = url.substring(index + 1);
      url = url.substring(0,index+1);
    }
    return new String[] {url, component};
  }

  public X509CRL getCRL(SearchResult result) {
    String bindingName = result.getName();
    X509CRL crl = null;
    // Retrieve attributes for that certificate.
    Attributes attributes = result.getAttributes();
    boolean isCA =false;
    try {
      isCA= isCAEntry(attributes);
    }
    catch (NamingException nexp) {
      if(log.isDebugEnabled()) {
	log.debug("Could not retrieve the attributes for :"+bindingName);
	nexp.printStackTrace();
      }
      return null;
    }

    if(!isCA) {
      return crl;
    }
    try {
      crl=getCRL(attributes);
    }
    catch (Exception nexp) {
      if(log.isDebugEnabled()) {
	log.debug("Could not fetch CRL from ldap for ::"+ bindingName);
	nexp.printStackTrace();
      }
    }
    return crl;

  }

  /** Get a certificate given a SearchResult */
  public LdapEntry getCertificate(SearchResult result) {
    String bindingName = result.getName();

    X509Certificate certificate = null;
    LdapEntry ldapEntry = null;
    String uniqueIdentifier = null;
    CertificateRevocationStatus status = null;

    // Retrieve attributes for that certificate.
    Attributes attributes = result.getAttributes();
    boolean isCA =false;
    synchronized(_contextLock) {
      DirContext context = null;
      try {
	context = contextHolder.getContext();
      }
      catch (javax.naming.NamingException e) {
	log.warn("Unable to get certificate:" + e);
      }
      if (log.isDebugEnabled()) {
	log.debug("Context is:" + context);
      }
    }
    // Check the revocation status of that certificate.
    status = getCertificateRevocationStatus(attributes);

    uniqueIdentifier = getUniqueIdentifier(attributes);

    if (log.isDebugEnabled()) {
      log.debug("look up:" + bindingName);
    }

    try {
      isCA= isCAEntry(attributes);
      /*
	Attributes attributes1=context.getAttributes(bindingName);
	String pem_cert = (String) context.lookup(bindingName);

	ByteArrayInputStream inputstream =
	new ByteArrayInputStream(pem_cert.getBytes());

	// Extract X509 certificates from the input stream.
	// Only one certificate should be stored in the ldap entry.
	byte abyte1[] = CertificateUtility.base64_to_binary(inputstream);
	Collection certs =
	CertificateUtility.parseX509orPKCS7Cert(new ByteArrayInputStream(abyte1));
	Iterator i = certs.iterator();
	if (i.hasNext()) {
	certificate = (X509Certificate) i.next();
	}*/
      certificate=getCertificate(attributes);
    }
    catch(Exception ex) {
      if(log.isDebugEnabled()) {
	log.debug("Unable to fetch ldap entry for " + bindingName);
	ex.printStackTrace();
      }
    }
    if (certificate != null) {
      if(isCA)
	ldapEntry = new LdapEntry(certificate, uniqueIdentifier, status,CertificateType.CERT_TYPE_CA);
      else
	ldapEntry = new LdapEntry(certificate, uniqueIdentifier, status,CertificateType.CERT_TYPE_END_ENTITY);
    }
    return ldapEntry;
  }

  /** returns certificate associated with the attributes
   */
  public  X509Certificate getCertificate(Attributes attributes) throws CertificateException, NamingException
    {

      X509Certificate certificate = null;
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      ByteArrayInputStream bais=null ;
      boolean isCA=isCAEntry(attributes);
      Attribute objectclassattribute=null;

      if(isCA) {
        objectclassattribute=attributes.get(CACERTIFICATE_ATTRIBUTE);
        byte []cacert=(byte [])objectclassattribute.get();
        bais = new ByteArrayInputStream(cacert);
      }
      else {
        objectclassattribute=attributes.get(USERCERTIFICATE_ATTRIBUTE);
        byte []usercert=(byte [])objectclassattribute.get();
        bais = new ByteArrayInputStream(usercert);

      }

      Collection certs =cf.generateCertificates(bais);
      Iterator i = certs.iterator();
      if (i.hasNext()) {
        certificate = (X509Certificate) i.next();
      }

      return certificate;

    }
  public  boolean isCAEntry(Attributes attributes)throws NamingException
    {
      Attribute objectattribute=attributes.get("objectclass");
      boolean isca=false;
      NamingEnumeration namingenum=objectattribute.getAll();
      while(namingenum.hasMore()){
        String value=(String)namingenum.next();
        if(value.equalsIgnoreCase(OBJECTCLASS_CERTIFICATIONAUTHORITY))  {
          isca=true;
          return isca;
        }
      }
      return isca;
    }

  /** Returns the CRL for the give CA certificate */
  private X509CRL getCRL(Attributes attributes) throws CRLException , NamingException, CertificateException {

    X509CRL crl = null;
    Attribute objectclassattribute=null;
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    ByteArrayInputStream bais=null ;
    objectclassattribute=attributes.get(CERTIFICATEREVOCATIONLIST_ATTRIBUTE);
    byte []cacert=(byte [])objectclassattribute.get();
    bais = new ByteArrayInputStream(cacert);
    Collection crls =cf.generateCRLs(bais);
    Iterator i = crls.iterator();
    if (i.hasNext()) {
      crl = (X509CRL) i.next();
    }

    return crl;
  }

  /** Return the unique identifier of the certificate. */
  private String getUniqueIdentifier(Attributes attributes) {
    Attribute att_uid = attributes.get(UID_ATTRIBUTE);
    String sz_uid = null;
    try {
      sz_uid = (String)att_uid.get();
    }
    catch (NamingException e) {
      if (log.isDebugEnabled()) {
	log.debug("Unable to get unique identifier: " + e);
	e.printStackTrace();
      }
    }
    return sz_uid;
  }

  /** Return the revocation status of the certificate. */
  public  CertificateRevocationStatus getCertificateRevocationStatus(Attributes attributes) {
    CertificateRevocationStatus status = null;

    // Retrieve the certificate status
    Attribute att_status = attributes.get(STATUS_ATTRIBUTE);
    String sz_status = null;
    try {
      sz_status = (String)att_status.get();
    }
    catch (NamingException e) {
      if (log.isDebugEnabled()) {
	log.debug("Unable to check revocation status: " + e);
	e.printStackTrace();
      }
      return status;
    }
    if (sz_status != null) {
      int st = Integer.valueOf(sz_status).intValue();
      switch (st) {
      case 1:
	status = CertificateRevocationStatus.VALID;
	break;
      case 3:
	status = CertificateRevocationStatus.REVOKED;
	break;
      default:
	status = CertificateRevocationStatus.UNKNOWN;
      }
    }
    if (log.isDebugEnabled()) {
      log.debug("Certificate status:" + status);
    }
    return status;
  }

  public X509CRL getCRL(String distingushName)
    {
      log.debug("Get CRl called  " );
      X509CRL crl=null;
      StringBuffer  filter=new StringBuffer();
      String searchfilter= parseDN(distingushName);
      filter.append(searchfilter);
      NamingEnumeration namingenum= internalSearchWithFilter(filter.toString());
      SearchResult  result=null;
      try {
        if(namingenum!=null) {
          log.debug("Get CRl serch result is not null  " );
          if(namingenum.hasMore()) {
            result=(SearchResult)namingenum.next();
          }
        }
        else {
          log.debug("Returning Get CRl serch result -1 " );
          return crl;
        }
      }
      catch (NamingException nexp) {
        if(log.isWarnEnabled()) {
          log.warn("Could not find CRL entry with filter:"+ filter.toString() + ". Reason: " + nexp);
        }
        log.debug("Returning Get CRl serch result -2 " );
        return null;
      }
      if(result!=null) {
        crl= getCRL(result);
      }
      log.debug("Returning Get CRl serch result -3 " );
      return crl;
      //return new Hashtable();
    }

  /********************************************************************************
   * CertDirectoryServiceCA interface. */

  public void publishCertificate(X509Certificate cert,
				 int type,
				 PrivateKey privatekey)
    throws javax.naming.NamingException {
    if (!initializationOK) {
      String msg = "Unable to publish Certificate. Root cause:" + rootCauseMsg;
      log.error(msg);
      throw new RuntimeException(msg);
    }
    Attributes set = new BasicAttributes(true);
    String dnname = cert.getSubjectDN().getName();
    if(log.isDebugEnabled()) {
      log.debug("Publish certificate, dn:" + dnname);
    }
    try {
      setLdapAttributes(cert, set, type,privatekey);

      // Set unique identifier
      String dn = "uniqueIdentifier=" + CertificateUtility.getUniqueIdentifier(cert);
      //getDigestAlgorithm(cert) + "-" + getHashValue(cert);
      //String dn =  "cn=" + getHashValue(cert);

      /* String pem_cert = null;
	 pem_cert =
	 CertificateUtility.base64encode(cert.getEncoded(),
	 CertificateUtility.PKCS7HEADER,
	 CertificateUtility.PKCS7TRAILER);
	 if (log.isDebugEnabled()) {
	 log.debug("About to publish LDAP entry:" + set.toString());
	 }*/
      // if(type==CertificateUtility.CACert) {
      synchronized (_contextLock) {
	DirContext context = contextHolder.getContext();
	context.createSubcontext(dn,set);
      }
      if (log.isInfoEnabled()) {
	log.info("Successfully published certificate in LDAP: " + dnname
                 + " URL: " + getDirectoryServiceURL());
      }
      /* }
	 else {
	 context.bind(dn, pem_cert, set);
	 }*/
    }
    catch(javax.naming.NameAlreadyBoundException nameexp) {
      if(log.isInfoEnabled()) {
	log.info("PublishCertificate: Name already exists: " +dnname);
      }
      throw nameexp;
    }
    catch(javax.naming.NamingException ex) {
      if(log.isWarnEnabled()) {
	log.warn("Unable to publish certificate: " + dnname
                 + " - Reason: " + ex.toString(), ex);
      }
      throw ex;
    }
  }

  public void publishCRLentry(X509CRLEntry crl) {
  }

  public SearchResult getLdapentry(String searchfilter,boolean uniqueid)
    throws MultipleEntryException, IOException  {

    StringBuffer filter=new StringBuffer();

    if(!uniqueid) {
      filter.append(searchfilter);
    }
    else {
      filter.append("(uniqueIdentifier=" +searchfilter + ")");
    }
    NamingEnumeration namingenum= internalSearchWithFilter(filter.toString());
    SearchResult  result=null;
    Attributes attributes=null;
    Vector activeentry=new Vector();
    try {
      if(namingenum!=null) {
	for(;namingenum.hasMore();) {
	  if(log.isDebugEnabled()) {
	    log.debug("Inside for loop of  get ldap entry :");
	  }
	  result=(SearchResult)namingenum.next();
	  dump(result);
	  log.debug("Result is " +result.toString());
	  attributes =result.getAttributes();
	  CertificateRevocationStatus status=
	    getCertificateRevocationStatus(attributes);
	  if(! status.equals(CertificateRevocationStatus.REVOKED)){
	    activeentry.add(result);
	  }
	  else {
	    if(log.isDebugEnabled()){
	      log.debug("Cert is revoked. filter: "
			+ filter.toString()
			+ " status is :"+status.toString());
	    }
	  }
	}
	// result=(SearchResult)namingenum.next();
	String resultMsg = null;
	if(log.isDebugEnabled() || activeentry.size()>1) {
	  resultMsg = "Search results: "
	    + filter.toString() + "  is :"
	    + activeentry.size()
	    + " result is :"
	    + (result == null ? null : result.toString());
	  log.debug(resultMsg);
	}
	if(activeentry.size()>1) {
	  String msg = "Found " + activeentry.size() + " active entries: "
	    + resultMsg;
	  log.info(msg);
	  //throw new MultipleEntryException(msg);
	}
	if (result == null && !activeentry.isEmpty()){
	  result=(SearchResult)activeentry.elementAt(0);
	}
      }
    }
    catch (NamingException nexp) {
      if(log.isDebugEnabled()) {
	log.debug("could not find entry with filter :"+ filter.toString());
	nexp.printStackTrace();
      }
    }
    return result;
  }

  public void dump (SearchResult result)
    throws NamingException {
    Attributes answer = result.getAttributes();
    for (NamingEnumeration ae = answer.getAll(); ae.hasMore();) {
      Attribute attr = (Attribute)ae.next();
      log.debug("attribute: " + attr.getID());
      /* Print each value */
      for (NamingEnumeration e = attr.getAll(); e.hasMore(); ) {
	log.debug("value: " + e.next());
      }
    }
  }


  public boolean revokeCertificate(String caBindingName,
				   String userBindingName,
				   PrivateKey caprivatekey,
				   String crlsignalg)
    throws NoSuchAlgorithmException,
    InvalidKeyException,
    CertificateException,
    CRLException,
    NoSuchProviderException,
    SignatureException,
    MultipleEntryException,
    IOException,
    NamingException  {

    if(log.isDebugEnabled()) {
      log.debug(" Binding name for ca : :"+caBindingName);
      log.debug(" Binding name for user : :"+userBindingName);
    }

    Attributes caAttributes=null;
    Attributes userAttributes=null;

    synchronized(_contextLock) {
      DirContext context = contextHolder.getContext();
      caAttributes= context.getAttributes(caBindingName);
      userAttributes=context.getAttributes(userBindingName);
    }

    X509CRL crl=null;
    crl= getCRL(caAttributes);

    X509Certificate caCert=getCertificate(caAttributes);
    X509Certificate userCert=getCertificate(userAttributes);
    X509Certificate issuercertificate = null;
    try {
      KeyRingService ksr;
      // Retrieve KeyRing service
      ksr = (KeyRingService)
	serviceBroker.getService(this,
				 KeyRingService.class,
				 null);

      X509Certificate[] certChain = ksr.buildCertificateChain(userCert);
      if (certChain.length > 1) {
	issuercertificate = certChain[1];
      }
      else {
	log.error("Certificate chain cannot be constructed.");
      }
    }
    catch (Exception e) {
      log.warn("Unable to build certificate chain of certificate to be revoked");
      return false;
    }
    PublicKey issuerPublicKey=issuercertificate.getPublicKey();
    
    X509CRL newCrl=CrlUtility.createCRL(caCert,crl,userCert,issuercertificate, caprivatekey,
                                        crlsignalg);
   
    try {
      updateCRLinLdap(caBindingName,newCrl,userBindingName);
    }
    catch (CRLException crlexp) {
      throw new IOException (" Got CRL exception while updating entry in LDAP :"+crlexp.getMessage());
    }
    catch (NamingException namingexp) {
      throw new IOException (" Got Naming  exception while updating entry in LDAP :"+namingexp.getMessage());
    }
    catch (Exception exp) {
      throw new IOException (" Got UnKnown   exception while updating entry in LDAP :"+exp.getMessage());
    }

    return true;
  }

  /** Build a search filter for LDAP based on the distinguished name
   */
  private String parseDN(String aDN)
    {
      String filter = "(&";

      StringTokenizer parser = new StringTokenizer(aDN, ",=");
      while(parser.hasMoreElements()) {
        String tok1 = parser.nextToken().trim().toLowerCase();
        String tok2 = parser.nextToken();
        if (tok1.equalsIgnoreCase("t")) {
          // Issue: OpenLdap does not recognize "t".
          tok1 = "title";
        }
        filter = filter + "(" + tok1 + "=" + tok2 + ")";
      }
      filter = filter + ")";
      if (log.isDebugEnabled()) {
        log.debug("Search filter is " + filter);
      }
      return filter;
    }

 


  public void updateCRLinLdap(String bindingname,X509CRL crl, String bindingname_revokedcert) throws CRLException,CertificateException, NamingException {

    String newstatus=revoked;
    Attribute attr1=new BasicAttribute(STATUS_ATTRIBUTE,newstatus);
    ModificationItem mit[]=new ModificationItem[1];
    ModificationItem miti=new ModificationItem(DirContext.REPLACE_ATTRIBUTE,attr1);
    mit[0]=miti;
    if(log.isDebugEnabled()) {
      log.debug("going to modify attribute in OpenLdap for user binding name :"+ bindingname_revokedcert);
    }
    synchronized(_contextLock) {
      DirContext context = contextHolder.getContext();
      context.modifyAttributes(bindingname_revokedcert,mit);

      byte[] crldata=crl.getEncoded();
      if(log.isDebugEnabled()) {
	log.debug("Recreating crl from byte data before updating LDAP");
      }
      X509CRL crl1=null;
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      ByteArrayInputStream bais=null ;
      // byte []cacert=(byte [])objectclassattribute.get();
      bais = new ByteArrayInputStream(crldata);
      Collection crls =cf.generateCRLs(bais);
      Iterator i = crls.iterator();
      if (i.hasNext()) {
	crl1 = (X509CRL) i.next();
      }
      if(log.isDebugEnabled()) {
	log.debug("Recreation of crl from byte data before updating LDAP over: " + crl1.toString());
      }

      attr1=new BasicAttribute( CERTIFICATEREVOCATIONLIST_ATTRIBUTE,crldata);
      mit=new ModificationItem[1];
      miti=new ModificationItem(DirContext.REPLACE_ATTRIBUTE,attr1);
      mit[0]=miti;
      if(log.isDebugEnabled()) {
	log.debug("going to modify attribute in OpenLdap  for CA "+bindingname );
	log.debug("new crl is :"+crl.toString());
      }
      context.modifyAttributes(bindingname,mit);
    }
  }

 

  private void setLdapAttributes(X509Certificate cert, Attributes set,int type,PrivateKey privatekey ) {

    if(log.isDebugEnabled())
      log.debug("+++++++ publish cert called  :"+type);
    Attribute objectclass = new BasicAttribute("objectclass");
    objectclass.add("top");;
    if(type==CertificateUtility.CACert) {
      objectclass.add(OBJECTCLASS_CERTIFICATIONAUTHORITY);
    }
    else {
      objectclass.add(OBJECTCLASS_INETORGPERSON);
    }
    set.put(objectclass);
    try {
      if(type==CertificateUtility.CACert) {
        X509CRL crl=CrlUtility.createEmptyCrl(cert.getSubjectDN().getName(),privatekey,"SHA1withRSA");
       	byte[] crldata=crl.getEncoded();
	byte [] crlauth=new byte[1];
	byte [] cacert=cert.getEncoded();
	set.put(AUTHORITYREVOCATIONLIST_ATTRIBUTE,crlauth);
	set.put(CERTIFICATEREVOCATIONLIST_ATTRIBUTE,crldata);
	set.put(CACERTIFICATE_ATTRIBUTE,cacert);
      }
      else {
	set.put(USERCERTIFICATE_ATTRIBUTE,cert.getEncoded());
      }
    }
    catch (Exception exp) {
      log.warn("Unable to set LDAP attributes for " + cert.getSubjectDN().getName());
    }

    // Set certificate status
    set.put(STATUS_ATTRIBUTE, "1");

    // Set Certificate hash
    set.put(UID_ATTRIBUTE, CertificateUtility.getHashValue(cert));

    // Set attributes from distinguished name.
    StringTokenizer parser = new StringTokenizer(cert.getSubjectDN().getName(), ",=");
    String ldapAttrib = null;
    while(parser.hasMoreElements()) {
      try {
        ldapAttrib = parser.nextToken().trim().toLowerCase();
        // 't' in certificate is 'title' in ldap
        if (ldapAttrib.equals("t"))
          ldapAttrib = "title";
        else if ("emailaddress".equals(ldapAttrib)) {
          ldapAttrib = "mail";
        } // end of else if ("emailaddress".equals(ldapAttrib))

	set.put(ldapAttrib,
		parser.nextToken());
      }
      catch(Exception ex) {
	if(log.isWarnEnabled()) {
	  log.warn("Unable to set LDAP attributes. DN=" + cert.getSubjectDN().getName()
		   + "ldapAttrib= " + ldapAttrib
		   + ". Reason: " + ex);
	}
      }
    }

    // Set serial number
    set.put("serialNumber",
	    cert.getSerialNumber().toString(16).toUpperCase());
  }
  public String getLdapURL() {
    return getDirectoryServiceURL();
  }


  public String getModifiedTimeStamp(String dn) {
    log.debug("getModifiedTimeStamp in open ldap called ");
    String lastmodified=null;
    StringBuffer  filter=new StringBuffer();
    String searchfilter= parseDN(dn);
    filter.append(searchfilter);
    log.debug("internalSearchWithFilter called in getModifiedTimeStamp of open ldap ");
    NamingEnumeration namingenum= internalSearchWithFilter(filter.toString());
    SearchResult  result=null;
    try {
      if(namingenum!=null) {
        log.debug("internalSearchWithFilter returned a non null result ");
	if(namingenum.hasMore()) {
	  result=(SearchResult)namingenum.next();
	}
      }
      else {
	return lastmodified;
      }
    }
    catch (NamingException nexp) {
      if(log.isWarnEnabled()) {
	log.warn("Could not get last modified attribute:"+ filter.toString() + ". Reason: " + nexp);
      }
      return null;
    }
    if(result!=null) {
      Attributes attributes = result.getAttributes();
      lastmodified = getLastModifiedTimeStamp(attributes);
    }
    log.debug("getModifiedTimeStamp in open ldap is returning  ");
    return  lastmodified;
  }

  private String getLastModifiedTimeStamp(Attributes attributes) {

    Attribute objectclassattribute=null;
    ByteArrayInputStream bais=null ;
    objectclassattribute=attributes.get(MODIFIEDTIMESTAMP);
    String modifiedtime=null;
    try {
      modifiedtime=(String)objectclassattribute.get();
    }
    catch(NamingException nexp) {
      log.info(" cannot get last modified time stamp");
    }
    return modifiedtime;

  }

}
