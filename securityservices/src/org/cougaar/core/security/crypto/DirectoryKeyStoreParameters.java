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

package org.cougaar.core.security.crypto;

import org.cougaar.core.component.ServiceBroker;

import java.io.InputStream;

public class DirectoryKeyStoreParameters {
  // LDAP server parameters
  //public String ldapServerUrl;
  //public int ldapServerType;

  // Keystore parameters
  public InputStream keystoreStream;
  public char[] keystorePassword;
  public String keystorePath;

  // CA Keystore parameters

  public InputStream caKeystoreStream;
  public char[] caKeystorePassword;
  public String caKeystorePath;

  // Run within a node or used as utility class by a CA?
  //public boolean isCertAuth;

  /** The default CA distinguished name. */
  //public String defaultCaDn;

  /** Used to get services that DirectoryService needs
   */
  public ServiceBroker serviceBroker;
}
