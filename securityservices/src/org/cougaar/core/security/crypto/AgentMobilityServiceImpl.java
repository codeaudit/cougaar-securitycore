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

import java.lang.*;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;

import org.cougaar.core.component.Service;
import org.cougaar.core.security.services.crypto.AgentMobilityService;

import com.nai.security.crypto.*;
import com.nai.security.util.CryptoDebug;

public class AgentMobilityServiceImpl implements AgentMobilityService {

  public Object moveAgentTo(String agentName, String targetNodeAgent)
  {
    /* Package the agent private and public keys.
     */
    byte[] pkcs12 = createPkcs12(agentName, targetNodeAgent);

    /* Remove the agent keys from the local keystore.
     * There should be a transaction here, otherwise we may end
     * up deleting keys before they have reached their destination.
     */

    return pkcs12;
  }

  public void moveAgentFrom(String agentName, Object cryptoAgentData)
  {
    /* Extract the keys from the PKCS12 envelope.
     */
    PrivateKeyCert[] kcert = extractPkcs12(agentName, cryptoAgentData);

    /* Install keys in the local keystore.
     */
  }

  /**
   */
  private byte[] createPkcs12(String agentName, String targetNodeAgent)
  {
    String nodeAgentName = null;

    /* Get the private key of the signer: the node agent.
     */
    if (CryptoDebug.debug) {
      System.out.println("========= Looking up key for sender node");
    }
    PrivateKey signerPrivKey = KeyRing.findPrivateKey(nodeAgentName);

    if (CryptoDebug.debug) {
      System.out.println("========= Looking up certificate for sender node");
    }
    X509Certificate signerCertificate =
      (X509Certificate)KeyRing.findCert(nodeAgentName);

    if (CryptoDebug.debug) {
      System.out.println("======== Looking up agent's key to be wrapped");
    }
    PrivateKey privKey = KeyRing.findPrivateKey(agentName);
    X509Certificate cert =
      (X509Certificate)KeyRing.findCert(agentName);

    if (CryptoDebug.debug) {
      System.out.println("======== Looking up key for target node");
    }
    PrivateKey rcvrPrivKey = KeyRing.findPrivateKey(targetNodeAgent);
    X509Certificate rcvrCert =
      (X509Certificate)KeyRing.findCert(targetNodeAgent);

    if (CryptoDebug.debug) {
      System.out.println("======== Creating PKCS#12 envelope");
    }
    byte[] pkcs12 = KeyRing.protectPrivateKey(privKey,
					      cert,
					      signerPrivKey,
					      signerCertificate,
					      rcvrCert);
    return pkcs12;
  }

  private PrivateKeyCert[] extractPkcs12(String agentName,
					 Object cryptoAgentData)
  {
    String nodeAgentName = null;
    byte[] pkcs12 = (byte[]) cryptoAgentData;

    PrivateKey rcvrPrivKey = KeyRing.findPrivateKey(nodeAgentName);
    X509Certificate rcvrCert =
      (X509Certificate)KeyRing.findCert(nodeAgentName);

    if (CryptoDebug.debug) {
      System.out.println("======== Extracting PKCS#12 envelope");
    }

    PrivateKeyCert[] pkey = KeyRing.getPfx(pkcs12,
					   rcvrPrivKey,
					   rcvrCert);
    return pkey;
  }
}
