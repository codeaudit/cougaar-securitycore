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
import javax.naming.*;
import javax.naming.directory.*;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRLEntry;

import com.nai.security.crypto.CertificateUtility;


public class OpenLdapCertDirectoryService extends CertDirectoryService
  implements CertDirectoryServiceClient, CertDirectoryServiceCA
{
  public OpenLdapCertDirectoryService(String aURL)
    throws Exception
  {
    super(aURL);
  }

  public void setDirectoryServiceURL(String aURL) {
    super.setDirectoryServiceURL(aURL);
    try {
      // TODO: secure authentication.
      context.addToEnvironment(Context.SECURITY_PRINCIPAL,
			       "cn=manager,dc=cougaar,dc=org");
      context.addToEnvironment(Context.SECURITY_CREDENTIALS, "secret");
    }
    catch (Exception e) {
      if (debug) {
	System.out.println("Unable to set directory service URL: " + e);
	e.printStackTrace();
      }
    }
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
    
    // Check the revocation status of that certificate.
    status = getCertificateRevocationStatus(attributes);

    uniqueIdentifier = getUniqueIdentifier(attributes);

    if (debug) {
      System.out.println("look up:" + bindingName);
    }

    try {
      if (debug) {
	System.out.println("Context is:" + context.toString());
      }
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
      }
    }
    catch(Exception ex) {
      if(debug) {
	System.out.print("Unable to fetch ldap entry for " + bindingName);
	ex.printStackTrace();
      }
    }
    if (certificate != null) {
      ldapEntry = new LdapEntry(certificate, uniqueIdentifier, status);
    }
    return ldapEntry;
  }

  /** Return the unique identifier of the certificate. */
  private String getUniqueIdentifier(Attributes attributes) {
    Attribute att_uid = attributes.get(UID_ATTRIBUTE);
    String sz_uid = null;
    try {
      sz_uid = (String)att_uid.get();
    }
    catch (NamingException e) {
      if (debug) {
	System.out.println("Unable to get unique identifier: " + e);
	e.printStackTrace();
      }
    }
    return sz_uid;
  }

  /** Return the revocation status of the certificate. */
  private CertificateRevocationStatus getCertificateRevocationStatus(Attributes attributes) {
    CertificateRevocationStatus status = null;

    // Retrieve the certificate status
    Attribute att_status = attributes.get(STATUS_ATTRIBUTE);
    String sz_status = null;
    try {
      sz_status = (String)att_status.get();
    }
    catch (NamingException e) {
      if (debug) {
	System.out.println("Unable to check revocation status: " + e);
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
    if (debug) {
      System.out.println("Certificate status:" + status);
    }
    return status;
  }

  public Hashtable getCRL()
  {
    return new Hashtable();
  }

  /********************************************************************************
   * CertDirectoryServiceCA interface. */

  public void publishCertificate(X509Certificate cert) {
    Attributes set = new BasicAttributes(true);
    String dnname = cert.getSubjectDN().getName();
    if(debug) {
      System.out.println("Publishing certificate, dn:" + dnname);
    }
    try {
      setLdapAttributes(cert, set);

      // Set unique identifier
      String dn = "uniqueIdentifier=" +
	getDigestAlgorithm(cert) + "-" + getHashValue(cert);
      //String dn =  "cn=" + getHashValue(cert);

      String pem_cert = null;
      pem_cert =
	CertificateUtility.base64encode(cert.getEncoded(),
					CertificateUtility.PKCS7HEADER,
					CertificateUtility.PKCS7TRAILER);
      if (debug) {
	System.out.println("About to publish LDAP entry:" + set.toString());
      }
      context.bind(dn, pem_cert, set);
    }
    catch(Exception ex) {
      ex.printStackTrace();
    }
  }

  public void publishCRLentry(X509CRLEntry crl) {
  }

  public boolean revokeCertificate(LdapEntry ldapentry) {
    /*
      if( ! cn.startsWith("cn="))cn = "cn=" + cn;
      try {
      certEntry = (LdapEntry)ctx.lookup(cn);
      certEntry.setStatus("3");
      ctx.rebind(cn, certEntry);
      }
      catch(Exception ex) {
      if(debug)ex.printStackTrace();
      }
      return certEntry;
    */
    return false;
  }

  /** Remove all the objects that satisfy the given filter.
   */
  public Object removeLdapEntry(String filter) 
  {
    Object obj = null;
    /*
    try {
      obj = context.lookup(cn); 
      context.unbind(cn);
    }
    catch(NamingException ex) {
      ex.printStackTrace();
    }
    */
    return obj;
  }

  private void setLdapAttributes(X509Certificate cert, Attributes set) {
    Attribute objectclass = new BasicAttribute("objectclass");
    //objectclass.add("xuda_certificate");
    objectclass.add("top");
    set.put(objectclass);

    // Set certificate status
    set.put(STATUS_ATTRIBUTE, "1");
    
    // Set Certificate hash
    set.put(UID_ATTRIBUTE, getHashValue(cert));

    // Set attributes from distinguished name.
    StringTokenizer parser = new StringTokenizer(cert.getSubjectDN().getName(), ",=");
    while(parser.hasMoreElements()) {
      try {
	set.put(parser.nextToken().trim().toLowerCase(), 
		parser.nextToken());
      }
      catch(Exception ex) {
	if(debug)ex.printStackTrace();
      }
    }

    // Set serial number
    set.put("serialNumber",
	    cert.getSerialNumber().toString(16).toUpperCase());
  }

}
