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
 * Created on September 12, 2001, 10:55 AM
 */

/**
 *
 * @author  rtripath
 * @version 
 */
package com.nai.security.crypto;

import java.util.*;

import java.io.InputStream;
import java.io.ByteArrayInputStream;

import java.security.*;
import java.security.cert.*;
import java.security.spec.*;

import javax.naming.*;
import javax.naming.directory.*;

import com.nai.security.certauthority.LdapEntry;

public class CertificateFinder  
{
  static private boolean debug = false;

  static private final int NETTOOLS = 1;
  static private final int OPENLDAP = 2;
  static private int ldapType = OPENLDAP;

  /** Creates new CertificateFinder */
  private String Provider_Url;
  private LdapClient client;
  public CertificateFinder(String url) 
  {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();
    try{
      Provider_Url=url;
      client=new LdapClient(Provider_Url);
    }catch(Exception e){
      System.err.println("failed to start LDAP client");
    }
  }
  public X509Certificate getCertificate(String commonName)
  { 
    NamingEnumeration search_results = client.search(commonName);
    int counter=0;
    X509Certificate certificate=null;
    if(ldapType == OPENLDAP) {
    while((search_results!=null)&&(search_results.hasMoreElements())) {
      try {
	SearchResult result = (SearchResult)search_results.next();
	LdapEntry entry = client.getLdapEntry(result.getName());
	if(entry.getStatus().trim().equals("3"))continue;
	
	certificate = entry.getCertificate();
	//verify CA signiture
	Principal issuer = certificate.getIssuerDN();
	java.security.cert.Certificate c = KeyRing.findCert(issuer);
	if (c == null) {
	  throw new CertificateException("Abort getting cert for " + 
	    commonName
	    + ", Unable to get CA certificate for verifying.");
	}
	PublicKey pk = c.getPublicKey();
	certificate.verify(pk);
      } catch(Exception ex) {
	  certificate = null;
	  ex.printStackTrace();
      }
    }
    return certificate;
    }
    else {
    while((search_results!=null)&&(search_results.hasMoreElements())) {
      try {
	SearchResult singleentry=(SearchResult)search_results.next();
	Attributes completeattributes=singleentry.getAttributes();
	Attribute x509cert=completeattributes.get("pem_x509");
	String cert=(String)x509cert.get();
	char[] charcert=cert.toCharArray();
	byte[] certdata=Base64.decode(charcert);
	try {
	  CertificateFactory certfactory=CertificateFactory.getInstance("X.509");
	  InputStream instream=new ByteArrayInputStream(certdata);
	  certificate=(X509Certificate)certfactory.generateCertificate(instream);
                
	  //verify CA signiture
	  Principal issuer = certificate.getIssuerDN();
	  java.security.cert.Certificate c = KeyRing.findCert(issuer);
	  if (c == null) {
	    throw new CertificateException("Abort getting cert for " + commonName
					   + ", Unable to get CA certificate for verifying.");
	  }
	  PublicKey pk = c.getPublicKey();
	  try {
	    certificate.verify(pk);
	  }catch(Exception e){
	    System.out.println("Could not verify CA:"+issuer+" signature");
	    certificate = null;
	  }
	}
	catch(CertificateException certexp) {
	  System.out.println("Could not generate certificate");
	  certexp.printStackTrace();

	}
				
	counter++;
      }
      catch (Exception exp) {
	exp.printStackTrace();
      }
    }
    if (debug) {
      System.out.println("value of counter is " + counter);
    }
    }
    return certificate; 
  }
  public Hashtable getCRL()
  {
    if(ldapType == OPENLDAP)return new Hashtable();
    String filter="(cert_status=3)";
    NamingEnumeration search_results= client.searchwithfilter(filter);
    int counter=0;
    Hashtable crl=new Hashtable();
    java.security.cert.Certificate certificate=null;
    while((search_results!=null)&&(search_results.hasMoreElements()))
      {
	try
	  {
	    SearchResult singleentry=(SearchResult)search_results.next();
	    Attributes completeattributes=singleentry.getAttributes();
	    Attribute x509cert=completeattributes.get("pem_x509");
	    Attribute aliasName=completeattributes.get("cn");
	    String cn =(String)aliasName.get();
	    String cert=(String)x509cert.get();
	    char[] charcert=cert.toCharArray();
	    byte[] certdata=Base64.decode(charcert);
	    try
	      {
		CertificateFactory certfactory=CertificateFactory.getInstance("X.509");
		InputStream instream=new ByteArrayInputStream(certdata);
		certificate=(java.security.cert.Certificate)certfactory.generateCertificate(instream);
                                        
	      }
	    catch(CertificateException certexp)
	      {
		System.out.println("Could not generate certificate");
		certexp.printStackTrace();

	      }
	    crl.put(cn, cert);
	  }
	catch(NamingException nameexception)
	  {
	    nameexception.printStackTrace();
	    System.out.println("Problem in getting individual object from result");
	  }
      }
                                        
    return crl;	
  }
  /*    public static void main (String args[])
	{
     
	CertificateFinder cf=new CertificateFinder("ldap://");
	Hashtable crl=cf.getCRL();
	
	}
  */	

}
