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

package org.cougaar.core.security.policy;

import sun.security.x509.*;
import java.net.*;

public class CaPolicy
  extends SecurityPolicy
{

  /** *************************************************************
   *  These fields are used by the CA and the node acting as a CA.
   */

  /** *************************
   *  Policy parameters when issuing certificates.
   */

  /** The X509 version number when an entity is issuing a
   *  certificate.
   */
  public int certVersion;

  /** The algorithm ID used to sign an X509 certificate.
   */
  public AlgorithmId algorithmId;

  /** The key size used to sign an X509 certificate.
   */
  public int keySize;

  /** The duration of the validity when issuing an X509 certificate.
   */
  public long howLong;

  /** *************************************************************
   *  These fields are used by the CA only.
   */

  /** The common name of the CA.
   */
  public String caCommonName;

  /** The distinguished name of the CA.
   */
  public X500Name caDnName;

  /** The URL of the LDAP directory where all certificates are
   *  published.
   */
  public String ldapURL;

  /** The type of LDAP directory where all certificates are published.
   */
  public int ldapType;
  // Values for ldapType
  static public final int NETTOOLS = 1;
  static public final int COUGAAR_OPENLDAP = 2;

  /** The name of a file where the next serial number is stored.
   */
  //public String serialNumberFile;

  /** The name of a directory where all pending requests are stored.
   */
  //public String pendingDirectory;

  /** The name of a directory where all denied requests are stored.
   */
  //public String deniedDirectory;

  /** The name of a directory where all PKCS10 requests are stored.
   */
  //public String pkcs10Directory;

  /** The name of a directory where all issued X509 certificates
   *  are stored.
   */
  //public String x509CertDirectory;

  /** *************************
   *  Policy parameters when issuing certificates.
   */

  /** Are certificates issuing automatically or are they stored
   *  in a pending queue until an administrator validates them?
   */
  public boolean requirePending;

  /** The algorithm ID used to sign CRLs
   */
  public AlgorithmId CRLalgorithmId;

  /**
   * Whether to allow node as signer, if yes node will sign agent
   * and other certificates requested. If not CA need to sign any
   * certificates requested.
   */
  public boolean nodeIsSigner;


  public String toString() {
    return "DN=" + caDnName
      + " - certVersion=" + certVersion
      + " - algorithmId=" + algorithmId
      + " - keysize=" + keySize
      + " - ldap=" + ldapURL;
  }

};
