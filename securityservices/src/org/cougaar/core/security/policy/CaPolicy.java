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


package org.cougaar.core.security.policy;

import org.cougaar.core.security.config.CaPolicyHandler;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

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
  public String algIdString;
  
  /** The key size used to sign an X509 certificate.
   */
  public int keySize;

  /** The duration of the validity when issuing an X509 certificate.
   */
  public long howLong;
  public String validity;

  /** The duration of the validity before issuing an X509 certificate.
   */
  public long timeEnvelope;
  public String timeEnvelopeString;
  
  /** *************************************************************
   *  These fields are used by the CA only.
   */

  /** The common name of the CA.
   */
  public String caCommonName;

  /** The distinguished name of the CA.
   */
  public X500Name caDnName;
  public String caDN;
  
  /** The URL of the LDAP directory where all certificates are
   *  published.
   */
  public String ldapURL;

  /** The principal used to establish a connection with the certificate
   *  directory service.
   */
  public String ldapPrincipal;

  /** The credential used to establish a connection with the certificate
   *  directory service.
   */
  public String ldapCredential;

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
  public String crlAlgIdString;
   
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

  public Node convertToXML(Document parent) {
    Element caPolicyNode = parent.createElement("certificateAuthority");
    Node node = null;
    // ca dn
    if(caDnName != null) {
      node = parent.createElement(CaPolicyHandler.CA_DN_ELEMENT);
      node.appendChild(parent.createTextNode(caDnName.getName()));
      caPolicyNode.appendChild(node);
    }
    // ldap url
    if(ldapURL != null) {
      node = parent.createElement(CaPolicyHandler.CA_LDAP_URL_ELEMENT);
      node.appendChild(parent.createTextNode(ldapURL));
      caPolicyNode.appendChild(node);
    }
    // ldap principal
    if(ldapPrincipal != null) {
      node = parent.createElement(CaPolicyHandler.CA_LDAP_PRINCIPAL_ELEMENT);
      node.appendChild(parent.createTextNode(ldapPrincipal));
      caPolicyNode.appendChild(node);
    }
    // ldap credential
    if(ldapCredential != null) {
      node = parent.createElement(CaPolicyHandler.CA_LDAP_CREDENTIAL_ELEMENT);
      node.appendChild(parent.createTextNode(ldapCredential));
      caPolicyNode.appendChild(node);
    }
    // ldap type
    String certDirType = "CougaarOpenLdap";
    if(ldapType != COUGAAR_OPENLDAP) {
      if(ldapType == NETTOOLS) {
        certDirType = "NetTools"; 
      }
      else {
        certDirType = "Unknown";
      }
    }
    node = parent.createElement(CaPolicyHandler.CA_LDAP_TYPE_ELEMENT);
    node.appendChild(parent.createTextNode(certDirType));
    caPolicyNode.appendChild(node);
 
    // clientCertPolicy node
    node = parent.createElement("clientCertPolicy");
    Node innerNode = null;
    // cert version
    innerNode = parent.createElement(CaPolicyHandler.CA_CERTVERSION_ELEMENT);
    innerNode.appendChild(parent.createTextNode((new Integer(certVersion)).toString()));
    node.appendChild(innerNode);
    // is node a signer
    innerNode = parent.createElement(CaPolicyHandler.CA_NODE_IS_SIGNER_ELEMENT);
    innerNode.appendChild(parent.createTextNode((new Boolean(nodeIsSigner)).toString()));
    node.appendChild(innerNode);
    // algorithm id
    if(algIdString != null) {
      innerNode = parent.createElement(CaPolicyHandler.CA_ALGORITHMID_ELEMENT);
      innerNode.appendChild(parent.createTextNode(algIdString));
      node.appendChild(innerNode);
    }
    // crl algorithm id
    if(crlAlgIdString != null) {
      innerNode = parent.createElement(CaPolicyHandler.CA_CRL_ALGORITHMID_ELEMENT);
      innerNode.appendChild(parent.createTextNode(crlAlgIdString));
      node.appendChild(innerNode);
    }
    // key size
    innerNode = parent.createElement(CaPolicyHandler.CA_KEYSIZE_ELEMENT);
    innerNode.appendChild(parent.createTextNode((new Integer(keySize)).toString()));
    node.appendChild(innerNode);
    // cert validity
    if(validity != null) {
      innerNode = parent.createElement(CaPolicyHandler.CA_CERTVALIDITY_ELEMENT);
      innerNode.appendChild(parent.createTextNode(validity));
      node.appendChild(innerNode);
    }
    // time envelope
    if(timeEnvelopeString != null) {
      innerNode = parent.createElement(CaPolicyHandler.CA_TIMEENVELOPE_ELEMENT);
      innerNode.appendChild(parent.createTextNode(timeEnvelopeString));
      node.appendChild(innerNode);
    }
    // require pending
    innerNode = parent.createElement(CaPolicyHandler.CA_REQUIREPENDING_ELEMENT);
    innerNode.appendChild(parent.createTextNode((new Boolean(requirePending)).toString()));
    node.appendChild(innerNode);
    // end clientCertPolicy node

    // add clientCertPolicy node to certificateAuthority node
    caPolicyNode.appendChild(node); 
    return caPolicyNode;
  }
};
