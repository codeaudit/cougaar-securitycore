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

// Cougaar core package
import org.cougaar.core.component.Service;

public interface SecurityPropertiesService extends Service
{
  /* DEBUG properties */
  public static String TRANSPORT_DEBUG =
  "org.cougaar.message.transport.debug";
  public static String SECURITY_DEBUG =
  "org.cougaar.security.info";
  public static String CRYPTO_DEBUG =
  "org.cougaar.core.security.crypto.debug";
  public static String CRYPTO_CRL_DEBUG =
  "org.cougaar.core.security.crypto.crldebug";
  public static String POLICY_DEBUG =
  "org.cougaar.core.security.policy.debug";
  public static String MONITORING_DEBUG =
  "org.cougaar.core.security.oldmonitoringdebug";
  public static String KAOS_DEBUG =
  "SAFE.debug";

  public static String COUGAAR_WORKSPACE =
  "org.cougaar.workspace";

  public static String BOOTSTRAP_KEYSTORE =
  "org.cougaar.core.security.bootstrap.keystore";
  public static String BOOTSTRAP_VERIFYKEY =
  "org.cougaar.core.security.bootstrap.verifyKeyUsage";
  public static String CRYPTO_CONFIG =
  "org.cougaar.security.crypto.config";
  public static String CA_CERTPATH =
  "org.cougaar.security.CA.certpath";
  public static String SECURITY_ROLE =
  "org.cougaar.security.role";
  public static String COUGAAR_INSTALL_PATH =
  "org.cougaar.install.path";
  public static String KEYSTORE_PASSWORD =
  "org.cougaar.security.keystore.password";
  public static String KEYSTORE_PATH =
  "org.cougaar.security.keystore";
  public static String BOOTSTRAP_LOGFILE =
  "org.cougaar.core.security.bootstrap.SecurityManagerLogFile";
  public static String CRL_POLLING_PERIOD =
  "org.cougaar.core.security.crypto.crlpoll";
  public static String VALIDITY_POLLING_PERIOD =
  "org.cougaar.core.security.crypto.validitypoll";
  public static String STAND_ALONE_MODE =
  "org.cougaar.core.security.standalone";
  public static String WEBSERVER_HTTPS_PORT =
  "org.cougaar.lib.web.https.port";

  public String getProperty(String property);
  public String getProperty(String property, String defaultValue);

  public void setProperty(String property, String value);

  /*
import org.cougaar.core.security.util.SecurityPropertiesService;
import org.cougaar.core.security.crypto.CryptoServiceProvider;

  private SecurityPropertiesService secprop = null;

    // TODO. Modify following line to use service broker instead
    secprop = CryptoServiceProvider.getSecurityProperties();

    secprop.CRYPTO_DEBUG
  */
}
