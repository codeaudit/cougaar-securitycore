/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.services.util;

// Cougaar core package
import org.cougaar.core.component.Service;

public interface SecurityPropertiesService
  extends Service
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
  public static String PM_SEARCH_PERIOD = 
  "org.cougaar.core.security.dataprotection.PMSearchPeriod";

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
