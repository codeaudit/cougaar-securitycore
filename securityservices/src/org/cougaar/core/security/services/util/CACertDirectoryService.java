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
package org.cougaar.core.security.services.util;

import org.cougaar.core.component.Service;
import org.cougaar.core.security.naming.CertificateEntry;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

public interface CACertDirectoryService
  extends Service
{
  /**
   * Return a list of all the certificates managed by the CA, including the CA itself.
   */
  List getAllCertificates();

  /**
   * Find a certificate given its unique identifier.
   * @param identifier - The unique identifier of the certificate to look for.
   */
  CertificateEntry findCertByIdentifier(String uniqueIdentifier);

  /**
   * Find a list of certificates matching a distinguished name.
   * @param identifier - The distinguished name of the certificate to look for.
   */
  List findCertByDistinguishedName(String distinguishedName);

  /**
   * Publish a certificate (managed by a CA) in the blackboard
   */
  void publishCertificate(X509Certificate clientX509,
			  int certType, PrivateKey pk);

  /**
   * Publish a certificate (managed by a CA) in the blackboard
   */
  void publishCertificate(CertificateEntry certEntry);

  void refreshBlackboard();
}
