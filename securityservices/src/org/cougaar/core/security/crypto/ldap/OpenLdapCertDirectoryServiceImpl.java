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
import javax.naming.*;
import javax.naming.directory.*;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CRL;
import java.security.cert.CertificateFactory;
import java.security.*;
import sun.security.x509.*;
import sun.security.util.*;
import java.lang.reflect.*;

import java.security.cert.CertificateException;
import java.security.cert.CRLException;
import javax.naming.NamingException;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceRevokedListener;
import org.cougaar.core.component.ServiceRevokedEvent;

import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.ldap.MultipleEntryException;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceClient;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceCA;
import org.cougaar.core.security.services.ldap.CertDirectoryServiceRequestor;
import org.cougaar.core.security.services.ldap.CertificateRevocationStatus;
import org.cougaar.core.security.services.ldap.LdapEntry;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.crlextension.x509.extensions.*;

public class OpenLdapCertDirectoryServiceImpl
  extends CertDirectoryService
  implements CertDirectoryServiceClient, CertDirectoryServiceCA
{
  public static final String issuingdpointname="IssuingDistibutionPoint";
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
    X509CRL crl=null;
    StringBuffer  filter=new StringBuffer();
    String searchfilter= parseDN(distingushName);
    filter.append(searchfilter);
    NamingEnumeration namingenum= internalSearchWithFilter(filter.toString());
    SearchResult  result=null;
    try {
      if(namingenum!=null) {
	if(namingenum.hasMore()) {
	  result=(SearchResult)namingenum.next();
	}
      }
      else {
	return crl;
      }
    }
    catch (NamingException nexp) {
      if(log.isWarnEnabled()) {
	log.warn("Could not find CRL entry with filter:"+ filter.toString() + ". Reason: " + nexp);
      }
      return null;
    }
    if(result!=null) {
      crl= getCRL(result);
    }

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
      setLdapAttributes(cert, set,type,privatekey);

      // Set unique identifier
      String dn = "uniqueIdentifier=" +
	getDigestAlgorithm(cert) + "-" + getHashValue(cert);
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

    String CA_DN=caCert.getSubjectDN().getName();
    X509Certificate userCert=getCertificate(userAttributes);
    PublicKey caPublicKey=caCert.getPublicKey();
    crl.verify(caPublicKey);

    Set crlentryset=crl.getRevokedCertificates();
    X509CRLEntry crlentry;
    Calendar calendar=Calendar.getInstance();
    Date current=calendar.getTime();
    calendar.add(Calendar.HOUR_OF_DAY,1);
    Date next =calendar.getTime();
    Vector crlentrys =new Vector();
    if((crlentryset!=null)&&(!crlentryset.isEmpty())) {
      Iterator i=crlentryset.iterator();
      for(;i.hasNext();) {
	crlentry=(X509CRLEntry)i.next();
	crlentrys.add(crlentry);
      }
    }
    crlentrys.trimToSize();
    if(log.isDebugEnabled()) {
      log.debug("Size of crl entry object from crl is : "
		+crlentrys.size());
    }
    X509CRLImpl crlimpl=null;
    X509CRLEntry[] crlentryarray=new X509CRLEntry[crlentrys.size()+1];
    crlentrys.copyInto(crlentryarray);

    X509Certificate issuercertificate = null;
    try {
      KeyRingService ksr;
      // Retrieve KeyRing service
      ksr = (KeyRingService)
	serviceBroker.getService(this,
				 KeyRingService.class,
				 null);

      X509Certificate[] certChain = ksr.checkCertificateTrust(userCert);
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

    /*
    String issuerdn=userCert.getIssuerDN().getName();
    String filterforIssuer=parseDN(issuerdn);
    SearchResult issuerresult=getLdapentry(filterforIssuer,false);
    if (issuerresult == null) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to get issuer certificate of "
		 + userCert.getSubjectDN().getName()
		 + " (No SearchResult) - Filter was:"
		 + filterforIssuer);
      }
      return false;
    }
    Attributes issuerattributes=issuerresult.getAttributes();
    if (issuerattributes == null) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to get issuer certificate of "
		 + userCert.getSubjectDN().getName() + " ( no Attributes)"
		 + " Filter was:" + filterforIssuer);
      }
      return false;
    }
    X509Certificate issuercertificate=getCertificate(issuerattributes);
    if (issuercertificate == null) {
      if (log.isWarnEnabled()) {
	log.warn("Unable to get issuer certificate of "
		 + userBindingName + " ( no X509 certificate)");
      }
      return false;
    }
    */

    PublicKey issuerPublicKey=issuercertificate.getPublicKey();
    String userDN=userCert.getSubjectDN().getName();
    CRLExtensions  extensions=null;
    X509CRLEntryImpl crlentryimpl=null;
    try {
      extensions= getExtensions(crl);
    }
    catch ( IOException ioexp) {
      ioexp.printStackTrace();
      throw new IOException(ioexp.getMessage());
    }

    if(issuerPublicKey.equals(caPublicKey)) {
      if(log.isDebugEnabled()) {
	log.debug("Both issuer of certificate & Revoking CA are same for user dn : "
		  + userDN +" Revoking CA : "+ CA_DN);
      }

      crlentryimpl=new X509CRLEntryImpl(userCert.getSerialNumber(),current);
      crlentryarray[crlentryarray.length-1]=crlentryimpl;

      if(extensions!=null) {
	crlimpl=
	  new X509CRLImpl(new X500Name(caCert.getSubjectDN().getName()),
			  current,next,crlentryarray,extensions);
      }
      else {
	crlimpl=
	  new X509CRLImpl(new X500Name(caCert.getSubjectDN().getName()),
			  current,next,crlentryarray);
      }


    }
    else {
      if(log.isDebugEnabled())
	log.debug(" Both issuer of certificate & Revoking CA are not *** same for user dn : "+ userDN +" Revoking CA : "+ CA_DN);
      //boolean indirectcrl=isIndirectCRLset(crl);
      IssuingDistributionPointExtension idpext=null;
      if(extensions!=null) {
	log.debug ("^^^^ GOT  ext:");
	idpext=getDistributionPointExtension(extensions);
      }
      if(idpext!=null) {
	log.debug ("^^^^ GOT  ext for idp:");
	Boolean indirectCRL=(Boolean)idpext.get(IssuingDistributionPointExtension.INDIRECT_CRL);
	if(!indirectCRL.booleanValue()) {
	  idpext.set(IssuingDistributionPointExtension.INDIRECT_CRL,new Boolean(true));
	  extensions.delete(issuingdpointname);
	  log.debug("%%%%%%%%%%%   extension after deleting :"+extensions.toString());
	  extensions.set(idpext.getName(),idpext);
	}
      }
      else {
	if(extensions==null) {
	  log.debug("Extension was null creating new extension ");
	  extensions=new CRLExtensions();
	}
	log.debug("Extension was not null  :"+extensions.toString());
	idpext=new  IssuingDistributionPointExtension (false,false,true);
	extensions.set(idpext.getName(),idpext);
	log.debug( " Issuing point extension created is :"+extensions.toString());
      }
      //CRLExtensions crlext=new CRLExtensions();//CertificateIssuerExtension
      log.debug("Going to create x500 name :"+ userCert.getIssuerDN().getName());
      X500Name username=new X500Name(userCert.getIssuerDN().getName());
      log.debug("Success in creating x500 name  :"+ username.toString());
      CougaarGeneralNames gns=	new  CougaarGeneralNames();
      log.debug("Success in creating GeneralNames");
      log.debug("before adding x500 name  GeneralNames");
      gns.add(username);
      CertificateIssuerExtension cie=new CertificateIssuerExtension();
      CertificateIssuerExtension certificateext=new  CertificateIssuerExtension(gns);
      CRLExtensions crlentryext =new CRLExtensions();
      log.debug(" going to set extension with name :"+certificateext.getName());
      crlentryext.set(certificateext.getName(),certificateext);

      if(log.isDebugEnabled())
	log.debug( "Certificate Issuer  extension created isCertificate issuer extension is  :"+crlentryext.toString());
      crlentryimpl=new X509CRLEntryImpl(userCert.getSerialNumber(),current,crlentryext);
      log.debug(" CRL entry object created is :"+crlentryimpl.toString());
      crlentryarray[crlentryarray.length-1]=crlentryimpl;
      crlimpl=new X509CRLImpl(new X500Name(caCert.getSubjectDN().getName()),current,next,crlentryarray,extensions);
      if(log.isDebugEnabled())
	log.debug(" new crl is after adding extensions in revoke certificate of Openldap is  : "+crlimpl.toString());
    }


    crlimpl.sign(caprivatekey,crlsignalg);

    try {
      updateCRLinLdap(caBindingName,crlimpl,userBindingName);
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

  public IssuingDistributionPointExtension getDistributionPointExtension(CRLExtensions crlextensions) {

    IssuingDistributionPointExtension  ext =(IssuingDistributionPointExtension)crlextensions.get(issuingdpointname);
    if(ext!=null) {
      log.debug(" got extension Idp ext:");
    }
    return ext;
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

  public CRLExtensions getExtensions(X509CRL crl) throws IOException {
    //Vector extension=new Vector();
    CRLExtensions extensions=new CRLExtensions();
    Set critSet =crl.getCriticalExtensionOIDs();
    boolean critical=true;
    boolean noncritical=false;
    String oid=null;
    DerInputStream dis=null;
    byte[]extensiondata=null;

    if (critSet != null && !critSet.isEmpty()) {
      if(log.isDebugEnabled())
	log.debug("Set of critical extensions:");
      for (Iterator i = critSet.iterator(); i.hasNext();) {
	oid = (String)i.next();
	String s1 = OIDMap.getName(new ObjectIdentifier(oid));
	extensiondata=crl.getExtensionValue(oid);
	dis=new DerInputStream(extensiondata);
	DerValue val=dis.getDerValue();
	byte[] byted=val.getOctetString();
	int ic = byted.length;
	Object obj = Array.newInstance(Byte.TYPE, ic);
	for(int j = 0; j < ic; j++)
	  Array.setByte(obj, j, byted[j]);
	try {
	  Class class1=OIDMap.getClass(new ObjectIdentifier(oid));
	  if(class1!=null) {
	    Class aclass[] = {
	      java.lang.Boolean.class, java.lang.Object.class
	    };
	    Constructor constructor = class1.getConstructor(aclass);
	    Object aobj[] = {
	      new Boolean(critical), obj
	    };
	    Extension  ext = (Extension)constructor.newInstance(aobj);
	    X509AttributeName x509attributename = new X509AttributeName(s1);
	    String s2 = x509attributename.getPrefix();
	    String s3;
	    if(s2.equalsIgnoreCase("x509"))  {
		int j = s1.lastIndexOf(".");
		s3 = s1.substring(j + 1);
	    } else
	      {
		s3 = s1;
	      }
	    if(log.isDebugEnabled()) {
	      log.debug("Got extension :"+s3);
	    }
	    extensions.set(s3,ext);

	  }
	  else {
	    throw new IOException (" Cannot create Extension for oid :"+oid);
	  }
	}
	catch (Exception exp) {
	  throw new IOException (" Cannot create Extension for oid :"+oid +"  for following reason :"+exp.getMessage());
	}
      }
    }
    if(log.isDebugEnabled())
      log.debug(" Going to create non critical Extension");
    critSet =crl.getNonCriticalExtensionOIDs();

    if (critSet != null && !critSet.isEmpty()) {
      if(log.isDebugEnabled())
	log.debug("Set non of critical extensions:");
      for (Iterator i = critSet.iterator(); i.hasNext();) {
	oid = (String)i.next();
	String s1 = OIDMap.getName(new ObjectIdentifier(oid));
	extensiondata=crl.getExtensionValue(oid);
	dis=new DerInputStream(extensiondata);
	DerValue val=dis.getDerValue();
	byte[] byted=val.getOctetString();
	int ic = byted.length;
	Object obj = Array.newInstance(Byte.TYPE, ic);
	for(int j = 0; j < ic; j++)
	  Array.setByte(obj, j, byted[j]);
	try {
	  Class class1=OIDMap.getClass(new ObjectIdentifier(oid));
	  if(class1!=null) {
	    Class aclass[] = {
	      java.lang.Boolean.class, java.lang.Object.class
	    };
	    Constructor constructor = class1.getConstructor(aclass);
	    Object aobj[] = {
	      new Boolean(noncritical), obj
	    };
	    Extension  ext = (Extension)constructor.newInstance(aobj);
	    extensions.set(s1,ext);
	  }
	  else {
	    if(log.isDebugEnabled())
	      log.debug(" Could not get class from oidmap for oid:"+oid);
	    continue;
	    //throw new IOException (" Cannot create Extension for oid :"+oid);
	  }
	}
	catch (Exception exp) {
	  if(log.isDebugEnabled()) {
	    log.debug(" Could not get class from oidmap for oid:"+oid);
	  }
	  continue;
	}
      }
    }

    log.debug("@@@@@@@@@@@ returning extensions :"+extensions.toString());
    return extensions;

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
	X509CRLEntry [] crlentry=new X509CRLEntry[1];
	X500Name name=new X500Name(cert.getSubjectDN().getName());
	log.debug("got name as : "+name.toString());
	Calendar c = Calendar.getInstance();
	Date current=c.getTime();
	log.debug("Current time is ::"+current.toString());
	c.set(2002,5,21);
	Date next=c.getTime();
	log.debug("Current time is ::"+next.toString());

	X509CRLImpl crl=new X509CRLImpl(name,current,next,null);

	crl.sign(privatekey,"SHA1withRSA");
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
      exp.printStackTrace();
    }

    // Set certificate status
    set.put(STATUS_ATTRIBUTE, "1");

    // Set Certificate hash
    set.put(UID_ATTRIBUTE, getHashValue(cert));

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
	if(log.isDebugEnabled()) {
	  log.debug("Error: DN=" + cert.getSubjectDN().getName()
			     + "ldapAttrib = " + ldapAttrib);
	  ex.printStackTrace();
	}
      }
    }

    // Set serial number
    set.put("serialNumber",
	    cert.getSerialNumber().toString(16).toUpperCase());
  }

}
