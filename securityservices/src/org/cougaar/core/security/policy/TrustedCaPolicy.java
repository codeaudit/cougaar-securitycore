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
import sun.security.x509.*;
import java.net.*;

public class TrustedCaPolicy {
  /** The alias of the certificate of a trusted CA in the keystore
   */
  //public String caAlias;

  /** The distinguished name of the trusted CA
   */
  public String caDN;

  /** The URL used to send a PKCS10 certificate signing request
   * to a CA
   */
  public String caURL;

  /** The URL used to retrieve public keys and certificates
   *  from a certificate directory service.
   */
  public String certDirectoryUrl;

  /** The principal used to establish a connection with the certificate
   *  directory service.
   */
  public String certDirectoryPrincipal;

  /** The credential used to establish a connection with the certificate
   *  directory service.
   */
  public String certDirectoryCredential;

  /** The type of certificate directory service
   *  (See below for a list of currently supported values)
   */
  public int certDirectoryType;

  private CertificateAttributesPolicy certificateAttributesPolicy;

  // Values for certDirectoryType
  static public final int NETTOOLS = 1;
  static public final int COUGAAR_OPENLDAP = 2;

  public CertificateAttributesPolicy getCertificateAttributesPolicy() {
    return certificateAttributesPolicy;
  }

  public void setCertificateAttributesPolicy(CertificateAttributesPolicy cap) {
    this.certificateAttributesPolicy = cap;
  }

  public String toString() {
    String s = " - caDN=" + caDN
      + " - caURL=" + caURL
      + " - certDirectoryURL=" + certDirectoryUrl
      + " - certDirectoryType=" + certDirectoryType;
    if (certificateAttributesPolicy != null) {
      s = s + "\nCertificate Attributes:" +  certificateAttributesPolicy.toString();
    }
    return s;
  }
 
  public Node convertToXML(Document parent) {
    Element trustedCANode = 
      parent.createElement(CryptoClientPolicyHandler.TRUSTED_CA_ELEMENT);
    Node node = null;
    // CA DN
    if(caDN != null) {
      node = parent.createElement(CryptoClientPolicyHandler.CA_DN_ELEMENT);
      node.appendChild(parent.createTextNode(caDN));
      trustedCANode.appendChild(node);
    }
    // CA url
    if(caURL != null) {
      node = parent.createElement(CryptoClientPolicyHandler.CA_URL_ELEMENT);
      node.appendChild(parent.createTextNode(caURL));
      trustedCANode.appendChild(node);
    }
    // cert directory url
    if(certDirectoryUrl != null) {
      node = parent.createElement(CryptoClientPolicyHandler.CERT_DIRECTORY_URL_ELEMENT);
      node.appendChild(parent.createTextNode(certDirectoryUrl));
      trustedCANode.appendChild(node);
    }
    // cert directory principal
    if(certDirectoryPrincipal != null) {
      node = parent.createElement(CryptoClientPolicyHandler.CERT_DIRECTORY_PRINCIPAL_ELEMENT);
      node.appendChild(parent.createTextNode(certDirectoryPrincipal));
      trustedCANode.appendChild(node);
    }
    // cert directory credential
    if(certDirectoryCredential != null) {
      node = parent.createElement(CryptoClientPolicyHandler.CERT_DIRECTORY_CREDENTIAL_ELEMENT);
      node.appendChild(parent.createTextNode(certDirectoryCredential));
      trustedCANode.appendChild(node);
    }
    // cert directory type
    String certDirType = "CougaarOpenLdap";
    if(certDirectoryType != COUGAAR_OPENLDAP) {
      if(certDirectoryType == NETTOOLS) {
        certDirType = "NetTools"; 
      }
      else {
        certDirType = "Unknown";
      }
    }
    node = parent.createElement(CryptoClientPolicyHandler.CERT_DIRECTORY_TYPE_ELEMENT);
    node.appendChild(parent.createTextNode(certDirectoryCredential));
    trustedCANode.appendChild(node);
    if(certificateAttributesPolicy != null) {
      // cert attributes for this trusted CA
      trustedCANode.appendChild(certificateAttributesPolicy.convertToXML(parent));
    }
    return trustedCANode;
  }
};
