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

import org.cougaar.core.security.config.CryptoClientPolicyHandler;

import org.w3c.dom.*;
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
    if (certificateAttributesPolicy == null) {
      TrustedCaPolicy[] tc = getIssuerPolicy();
      if (tc.length != 0) {
        return tc[0].getCertificateAttributesPolicy();
      }
    }
    return certificateAttributesPolicy;
  }
  public CertificateAttributesPolicy getCertificateAttributesPolicy(
    TrustedCaPolicy trustedCaPolicy) {
    if (trustedCaPolicy != null && trustedCaPolicy.getCertificateAttributesPolicy() != null)
      return trustedCaPolicy.getCertificateAttributesPolicy();

    return certificateAttributesPolicy;
  }

  public TrustedCaPolicy[] getTrustedCaPolicy() {
    TrustedCaPolicy[] tc = new TrustedCaPolicy[trustedCAs.size()];
    trustedCAs.toArray(tc);
    return tc;
  }

  public TrustedCaPolicy[] getIssuerPolicy() {
    Vector issuers = new Vector();
    for (int i = 0; i < trustedCAs.size(); i++) {
      TrustedCaPolicy trustedCaPolicy = (TrustedCaPolicy)trustedCAs.get(i);
      if (trustedCaPolicy.caURL != null) {
        issuers.addElement(trustedCaPolicy);
      }
    }
    TrustedCaPolicy[] tc = new TrustedCaPolicy[issuers.size()];
    issuers.toArray(tc);
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

  public Node convertToXML(Document parent) {
    Element ccPolicyNode = parent.createElement("cryptoClientPolicy");
    // is certificate authority
    Node node = parent.createElement(CryptoClientPolicyHandler.IS_CERT_AUTH_ELEMENT);    
    node.appendChild(parent.createTextNode((new Boolean(isCertificateAuthority)).toString()));
    ccPolicyNode.appendChild(node);
    
    if(keystoreName != null) {
      // keystore file name
      node = parent.createElement(CryptoClientPolicyHandler.KEYSTORE_FILE_ELEMENT);    
      node.appendChild(parent.createTextNode(keystoreName));
      ccPolicyNode.appendChild(node);
    }
    if(keystorePassword != null) {
      // keystore password (BAD, we shouldn't store the keystore password in the clear!)
      node = parent.createElement(CryptoClientPolicyHandler.KEYSTORE_PASSWORD_ELEMENT);    
      node.appendChild(parent.createTextNode(keystorePassword));
      ccPolicyNode.appendChild(node);
    }
    // KEYSTORE_USE_SMART_CARD optional
    /*
    node = parent.createElement(CryptoClientPolicyHandler.KEYSTORE_USE_SMART_CARD);    
    node.appendChild(parent.createTextNode((new Boolean(useSmartCard)).toString()));
    ccPolicyNode.appendChild(node);
    */
    // iterator the vector of trusted CAs
    node = parent.createElement("trustedCAs");
    // trusted CAs inner nodes
    Node innerNode = null;
    if(trustedCaKeystoreName != null) {
      // CA keystore
      innerNode = parent.createElement(CryptoClientPolicyHandler.CA_KEYSTORE_ELEMENT);
      innerNode.appendChild(parent.createTextNode(trustedCaKeystoreName));
      node.appendChild(innerNode);
    }
    if(trustedCaKeystorePassword != null) {
      // CA keystore password (shouldn't be storing passwords in the clear!)
      innerNode = parent.createElement(CryptoClientPolicyHandler.CA_KEYSTORE_PASSWORD_ELEMENT);
      innerNode.appendChild(parent.createTextNode(trustedCaKeystorePassword));
      node.appendChild(innerNode);
    }
    // iterator through the trusted CAs
    Iterator i = trustedCAs.iterator();
    while(i.hasNext()) {
      TrustedCaPolicy tcp = (TrustedCaPolicy)i.next();
      node.appendChild(tcp.convertToXML(parent));
    }
    ccPolicyNode.appendChild(node);
    if(certificateAttributesPolicy != null) {
      // certificate attributes
      ccPolicyNode.appendChild(certificateAttributesPolicy.convertToXML(parent));
    }
    return ccPolicyNode;
  }
};
