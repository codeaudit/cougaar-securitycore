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

// Cougaar security services
import com.nai.security.util.CryptoDebug;
import com.nai.security.policy.*;

public class CertDirectoryServiceFactory
{
  //private static boolean CryptoDebug.debug = false;


  public static CertDirectoryServiceClient getCertDirectoryServiceClientInstance(
					      int serverType, String serverUrl)
  {
    CertDirectoryServiceClient ldapClient = null;
    //System.out.println("%%%%%%%%%%%%  type found is : "+serverType);
    switch (serverType) {
    case TrustedCaPolicy.COUGAAR_OPENLDAP:
      ldapClient = new OpenLdapCertDirectoryService(serverUrl);
      break;
    case TrustedCaPolicy.NETTOOLS:
      ldapClient = new NetToolsCertDirectoryService(serverUrl);
      break;
    default:
      if (CryptoDebug.debug) {
	System.out.println("Client: Unknown directory service type: " + serverType);
      }
    }
    return ldapClient;
  }

  public static CertDirectoryServiceCA getCertDirectoryServiceCAInstance(
					      int serverType, String serverUrl)
  {
    CertDirectoryServiceCA instance = null;

    switch (serverType) {
    case TrustedCaPolicy.COUGAAR_OPENLDAP:
      instance = new OpenLdapCertDirectoryService(serverUrl);
      break;
    default:
      // Net Tools does not support CA functions programmatically.
      if (CryptoDebug.debug) {
	System.out.println("CA: Unknown directory service type: " + serverType);
      }
    }
    return instance;
  }
}








