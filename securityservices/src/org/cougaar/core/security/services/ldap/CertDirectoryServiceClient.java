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

package org.cougaar.core.security.services.ldap;

import java.util.Hashtable;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;

// Cougaar core services
import org.cougaar.core.component.Service;

import org.cougaar.core.security.crypto.ldap.LdapEntry;

public interface CertDirectoryServiceClient  extends Service  {

  /** Set the URL of the certificate directory service to look for */
  //void setDirectoryServiceURL(String aURL);

  /** Retrieve X509 certificates by common name */
  LdapEntry[] searchByCommonName(String commonName);

  /** Return a list of certificates that satisfy a search filter. */
  LdapEntry[] searchWithFilter(String filter);

  X509CRL  getCRL(String  distingushName);

  String getDirectoryServiceURL();
  int getDirectoryServiceType();
  String getModifiedTimeStamp(String dn);
}






