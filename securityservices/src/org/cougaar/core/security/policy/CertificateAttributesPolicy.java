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

/** This class contains the default attributes used to generate
 *  a certificate
 */
public class CertificateAttributesPolicy implements XMLSerializable {

  /** The default Organization Unit when generating a new certificate
   */
  public String ou;

  /** The default Organization when generating a new certificate
   */
  public String o;

  /** The default locality when generating a new certificate
   */
  public String l;

  /** The default State when generating a new certificate
   */
  public String st;

  /** The default country name when generating a new certificate
   */
  public String c;

  /** The default domain when generating a new certificate
   */
  public String domain;

  /** The algorithm used to generate the key
   */
  public String keyAlgName;

  /** The key size
   */
  public int keysize;

  /** The default period of validity
   */
  public long howLong;
  public String validity;
  
  /** The signature algorithm name
   */
  public String sigAlgName;

  /** Determines whether the node key is used to sign other keys in the node
   */
  public boolean nodeIsSigner;

  /** Determines when to regenerate keys
   */
  public long regenEnvelope;
  public String timeEnvelope;
  
  /**
   * Certificate Version, used for node to create agent certificate
   */
  public int certVersion;

  public String toString() {
    return "ou=" + ou + " - o=" + o + " - l=" + l + " - st=" + st
      + " - c=" + c + " - domain=" + domain
      + " - keysize=" + keysize
      + " - howLong=" + howLong
      + " - sigAlgName=" + sigAlgName
      + " - keyAlgName=" + keyAlgName;
  }
  
  public Node convertToXML(Document parent) {
    Element certAttrNode = 
      parent.createElement(CryptoClientPolicyHandler.CERTIFICATE_ATTR_ELEMENT);
    // distinguished name
    Node node = parent.createElement("distinguishedName");
    Node innerNode = null;
    // organizational unit
    if(ou != null) {
      innerNode = parent.createElement(CryptoClientPolicyHandler.OU_ELEMENT);
      innerNode.appendChild(parent.createTextNode(ou));
      node.appendChild(innerNode);
    }
    // organization
    if(o != null) {
      innerNode = parent.createElement(CryptoClientPolicyHandler.O_ELEMENT);
      innerNode.appendChild(parent.createTextNode(o));
      node.appendChild(innerNode);
    }
    // locality
    if(l != null) {
      innerNode = parent.createElement(CryptoClientPolicyHandler.L_ELEMENT);
      innerNode.appendChild(parent.createTextNode(l));
      node.appendChild(innerNode);
    }
    // state
    if(st != null) {
      innerNode = parent.createElement(CryptoClientPolicyHandler.ST_ELEMENT);
      innerNode.appendChild(parent.createTextNode(st));
      node.appendChild(innerNode);
    }
    // country
    if(c != null) {
      innerNode = parent.createElement(CryptoClientPolicyHandler.C_ELEMENT);
      innerNode.appendChild(parent.createTextNode(c));
      node.appendChild(innerNode);
    }
    // domain
    if(domain != null) {
      innerNode = parent.createElement(CryptoClientPolicyHandler.DOMAIN_ELEMENT);
      innerNode.appendChild(parent.createTextNode(domain));
      node.appendChild(innerNode);
    }
    certAttrNode.appendChild(node);
    // node is signer
    node = parent.createElement(CryptoClientPolicyHandler.NODE_IS_SIGNER_ELEMENT);
    node.appendChild(parent.createTextNode((new Boolean(nodeIsSigner)).toString()));
    certAttrNode.appendChild(node);
    // key algorithm
    node = parent.createElement(CryptoClientPolicyHandler.KEYALGNAME_ELEMENT);
    node.appendChild(parent.createTextNode(keyAlgName));
    certAttrNode.appendChild(node);
     // key size
    node = parent.createElement(CryptoClientPolicyHandler.KEYSIZE_ELEMENT);
    node.appendChild(parent.createTextNode((new Integer(keysize)).toString()));
    certAttrNode.appendChild(node);
    // signing algorithm
    node = parent.createElement(CryptoClientPolicyHandler.SIGALGNAME_ELEMENT);
    node.appendChild(parent.createTextNode(sigAlgName));
    certAttrNode.appendChild(node);
    // cert validity
    node = parent.createElement(CryptoClientPolicyHandler.VALIDITY_ELEMENT);
    node.appendChild(parent.createTextNode(validity));
    certAttrNode.appendChild(node);
    // cert time envelope
    node = parent.createElement(CryptoClientPolicyHandler.ENVELOPE_ELEMENT);
    node.appendChild(parent.createTextNode(timeEnvelope));
    certAttrNode.appendChild(node);
    return certAttrNode;
  }
};
