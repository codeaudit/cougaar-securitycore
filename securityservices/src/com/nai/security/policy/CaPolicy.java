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

package com.nai.security.policy;

import sun.security.x509.*;
import java.net.*;

public class CaPolicy {

  public String keyStoreFile;
  public String keyStorePassword;
  public String caCommonName;

  public String ldapURL;
  public int ldapType;
  // Values for ldapType
  static public final int NETTOOLS = 1;
  static public final int COUGAAR_OPENLDAP = 2;

  public String serialNumberFile;
  public String pkcs10Directory;
  public String x509CertDirectory;
  public String pendingDirectory;
  public String deniedDirectory;

  // Client policy
  public int certVersion;
  public AlgorithmId algorithmId;
  public int keySize;
  public long howLong;
  public boolean requirePending;
  public AlgorithmId CRLalgorithmId;
};
