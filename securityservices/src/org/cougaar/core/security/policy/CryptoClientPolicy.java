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

import java.util.*;

public class CryptoClientPolicy
  extends SecurityPolicy
{
  private boolean isCertificateAuthority;

  private boolean isRootCA;

  /** The file name of the keystore containing keys for this node
   */
  private String keystoreName;

  /** The password of the keystore containing keys for this node
   */
  private String keystorePassword;

  /** The file name of the keystore containing the trusted CAs
   */
  private String trustedCaKeystoreName;

  /** The password of the keystore containing the trusted CAs.
   */
  private String trustedCaKeystorePassword;

  /** An array of trusted certificate authorities (TrustedCaPolicy).
   */
  private Vector trustedCAs;

  /** Flag to indicate whether the smart card is to be used
   * in conjunction with keystore.
   */
  private boolean useSmartCard = false;

  private CertificateAttributesPolicy certificateAttributesPolicy;

  public CryptoClientPolicy() {
    trustedCAs = new Vector();
  }

  // Get methods
  public boolean isCertificateAuthority() {
    return isCertificateAuthority;
  }

  public boolean isRootCA() {
    return isRootCA;
  }

  public String getKeystoreName() {
    return keystoreName;
  }
  public String getKeystorePassword() {
    return keystorePassword;
  }
  public boolean getUseSmartCard() {
    return useSmartCard;
  }

  public String getTrustedCaKeystoreName() {
    return trustedCaKeystoreName;
  }
  public String getTrustedCaKeystorePassword() {
    return trustedCaKeystorePassword;
  }
  public CertificateAttributesPolicy getCertificateAttributesPolicy() {
    return certificateAttributesPolicy;
  }
  public TrustedCaPolicy[] getTrustedCaPolicy() {
    TrustedCaPolicy[] tc = new TrustedCaPolicy[trustedCAs.size()];
    trustedCAs.toArray(tc);
    return tc;
  }

  // Set methods
  public void setIsCertificateAuthority(boolean isCertAuth) {
    isCertificateAuthority = isCertAuth;
  }

  public void setIsRootCA(boolean isRoot) {
    isRootCA = isRoot;
  }

  public void setKeystoreName(String keystoreName) {
    this.keystoreName = keystoreName;
  }
  public void setKeystorePassword(String keystorePassword) {
    this.keystorePassword = keystorePassword;
  }
  public void setUseSmartCard(boolean flag) {
    this.useSmartCard = flag;
  }

  public void setTrustedCaKeystoreName(String trustedCaKeystoreName) {
    this.trustedCaKeystoreName = trustedCaKeystoreName;
  }
  public void setTrustedCaKeystorePassword(String trustedCaKeystorePassword) {
    this.trustedCaKeystorePassword = trustedCaKeystorePassword;
  }

  public void setCertificateAttributesPolicy(CertificateAttributesPolicy cap) {
    this.certificateAttributesPolicy = cap;
  }
  public void addTrustedCaPolicy(TrustedCaPolicy tc) {
    trustedCAs.addElement(tc);
  }

  public String toString() {
    String s = "isCA=" + isCertificateAuthority
      + " - keystoreName=" + keystoreName
      + " - trustedCaKeystoreName=" + trustedCaKeystoreName;
    if (trustedCAs != null) {
      for (int i = 0 ; i < trustedCAs.size() ; i++) {
	s = s + "\nTrusted CA[" + i + "]:" + trustedCAs.get(i).toString();
      }
    }
    if (certificateAttributesPolicy != null) {
      s = s + "\nCertificate Attributes:" +  certificateAttributesPolicy.toString();
    }
    return s;
  }

};
