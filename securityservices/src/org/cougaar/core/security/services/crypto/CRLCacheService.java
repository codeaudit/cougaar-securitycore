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

package org.cougaar.core.security.services.crypto;

import java.lang.*;
import java.security.cert.X509Certificate;
import java.security.Principal;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.*;
import java.security.cert.*;
import sun.security.x509.*;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyStoreException;

// Cougaar
import org.cougaar.core.component.Service;
import org.cougaar.core.service.BlackboardService;

// Cougaar Security Services
import org.cougaar.core.security.crypto.*;

/** Low-level service to update and retrive certificates and private keys from the Certificate Cache 
 */
public interface CRLCacheService extends Service {
  boolean isCertificateInCRL(X509Certificate subjectCertificate, String IssuerDN);
  void addToCRLCache(String dnname,String ldapURL,int ldapType);
  long getSleeptime();
  void setSleeptime(long sleeptime);
  String getLastModifiedTime(String dnname);
  void updateCRLCache(CRLWrapper wrapperFromDirectory);
  void setBlackboardService (BlackboardService bbs);
  
}
