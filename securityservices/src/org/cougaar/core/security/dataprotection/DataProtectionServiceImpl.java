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

package org.cougaar.core.security.dataprotection;

import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.security.cert.*;

import sun.security.x509.*;

// Cougaar core infrastructure
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.service.LoggingService;

// Overlay
import org.cougaar.core.service.*;

// Cougaar security services
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.services.crypto.*;
import org.cougaar.core.security.crypto.*;
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.DataFailureEvent;


public class DataProtectionServiceImpl
  implements DataProtectionService
{
  private ServiceBroker serviceBroker;
  private EncryptionService encryptionService;
  private CryptoPolicyService cps;
  private KeyRingService keyRing;
  private LoggingService log;
  private DataProtectionServiceClient dpsClient;

  private String keygenAlg = "DES";
  private String digestAlg = "SHA";

  // event publisher for data protection failures
  private static EventPublisher eventPublisher;

  // add event publisher
  public static void addPublisher(EventPublisher publisher) {
    if(eventPublisher == null) {
      eventPublisher = publisher;
    }
  }

  public DataProtectionServiceImpl(ServiceBroker sb, Object requestor)
  {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    // Get encryption service
    encryptionService = (EncryptionService)
      serviceBroker.getService(requestor,
			       EncryptionService.class,
			       null);

    // Get crypto policy service
    cps = (CryptoPolicyService)
      serviceBroker.getService(requestor,
			       CryptoPolicyService.class,
			       null);

    // Get keyring service
    keyRing = (KeyRingService)
      serviceBroker.getService(requestor,
			       KeyRingService.class,
			       null);

    if (encryptionService == null) {
       throw new RuntimeException("Encryption service not available");
    }
    if (cps == null) {
       throw new RuntimeException("Policy service not available");
    }
    if (keyRing == null) {
       throw new RuntimeException("KeyRing service not available");
    }

    if (!(requestor instanceof DataProtectionServiceClient)) {
      throw new RuntimeException("Requestor is not DataProtectionServiceClient");
    }
    dpsClient = (DataProtectionServiceClient)requestor;

    try {
      reprotectClient(dpsClient, null);
    } catch (GeneralSecurityException gsx) {
      if (log.isDebugEnabled())
        log.debug("Exception occured while reprotecting keys: " + gsx.toString());
    }
  }

  public OutputStream getOutputStream(DataProtectionKeyEnvelope pke,
				      OutputStream os)
	throws IOException, GeneralSecurityException
  {

    String agent = dpsClient.getAgentIdentifier().toAddress();

    if (log.isDebugEnabled())
      log.debug("getOutputStream for " + agent);

    // check if there is key and certificate created for the client
    List certList = keyRing.findCert(agent);
    if (certList == null || certList.size() == 0) {
      CertificateException cx = new CertificateException("No certificate available to sign.");
      publishDataFailure(agent, DataFailureEvent.NO_CERTIFICATES, cx.toString());
      throw cx;
    }
    DataProtectionKey dpKey = null;
    try {
      dpKey = pke.getDataProtectionKey();
    }
    catch (Exception ioe) {
    }
    if (dpKey == null) {
      try {
        dpKey = createDataProtectionKey(agent);
      }
      catch(GeneralSecurityException gsx) {
        publishDataFailure(agent, DataFailureEvent.CREATE_KEY_FAILURE, gsx.toString());
        throw gsx;
      }
      catch(IOException iox) {
        publishDataFailure(agent, DataFailureEvent.IO_EXCEPTION, iox.toString());
        throw iox;
      }
      pke.setDataProtectionKey(dpKey);
    }

    SecureMethodParam policy = ((DataProtectionKeyImpl)dpKey).getSecureMethod();
    if (policy.secureMethod == SecureMethodParam.PLAIN)
      return os;

    // check whether key needs to be replaced
    DataProtectionOutputStream dpos =
      new DataProtectionOutputStream(os, pke, agent, serviceBroker);
    dpos.addPublisher(eventPublisher);
    return dpos;
  }

  private DataProtectionKey createDataProtectionKey(String agent)
    throws GeneralSecurityException, IOException {
    //SecureMethodParam policy =
    cps.getSendPolicy(agent, agent);
    SecureMethodParam policy = cps.getDataProtectionPolicy(agent);
    if (policy == null) {
       RuntimeException rte = new RuntimeException("Could not find data protection policy for " + agent);
       publishDataFailure(agent, DataFailureEvent.INVALID_POLICY, rte.toString());
       throw rte;
    }
    if (policy.secureMethod == SecureMethodParam.ENCRYPT
      || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      SecureRandom random = new SecureRandom();
      KeyGenerator kg = KeyGenerator.getInstance(keygenAlg);
      kg.init(random);
      SecretKey sk = kg.generateKey();
      List certList = keyRing.findCert(agent);
      if (certList == null || certList.size() == 0) {
        CertificateException cex = new CertificateException("Can not find agent cert: "+ agent);
        throw cex;
      }
      CertificateStatus cs = (CertificateStatus)certList.get(0);
      X509Certificate agentCert = (X509Certificate)cs.getCertificate();

      SealedObject skeyobj = encryptionService.asymmEncrypt(agent,
        policy.asymmSpec, sk, agentCert);
      return new DataProtectionKeyImpl(skeyobj, digestAlg, policy);
    }
    return new DataProtectionKeyImpl(null, digestAlg, policy);
  }

  public void reprotectClient(DataProtectionServiceClient client, PrivateKey oldkey)
    throws GeneralSecurityException
  {
    String agent = dpsClient.getAgentIdentifier().toAddress();
    if (log.isDebugEnabled())
      log.debug("reprotecting client:" + agent);

    Iterator keys = client.iterator();
    if (keys == null)
      return;

    while (keys.hasNext()) {
      try {
        DataProtectionKeyEnvelope pke = (DataProtectionKeyEnvelope)
          keys.next();

        DataProtectionKeyImpl dpKey = (DataProtectionKeyImpl)pke.getDataProtectionKey();
        if (dpKey == null)
          continue;

        String spec = dpKey.getSecureMethod().asymmSpec;

        List keyList = null;
        if (oldkey != null) {
          keyList = new Vector();
          keyList.add(oldkey);
        }
        else
          keyList = keyRing.findPrivateKey(agent, false);
        if (keyList == null || keyList.size() == 0) {
          GeneralSecurityException gsx =
            new GeneralSecurityException("No private key available to decrypt");
          publishDataFailure(agent, DataFailureEvent.NO_PRIVATE_KEYS, gsx.toString());
          throw gsx;

        }
        Iterator it = keyList.iterator();
        SecretKey skey = null;

        SealedObject obj = (SealedObject)dpKey.getObject();
        while (it.hasNext()) {
          PrivateKeyCert cs = (PrivateKeyCert) it.next();
          try {
            X509Certificate [] certList = keyRing.checkCertificateTrust(
              (X509Certificate)cs.getCertificateStatus().getCertificate());
            if (certList.length == 0) {
              if (log.isDebugEnabled())
                log.debug("Certificate not trusted.");
              continue;
            }
          } catch (CertificateException ex) {
            if (ex instanceof CertificateExpiredException) {
              if (log.isDebugEnabled())
                log.debug("Private key expired.");
            }
            else {
              if (log.isDebugEnabled())
                log.debug("Private key not trusted.");
              continue;
            }
          }

          PrivateKey key = cs.getPrivateKey();
          if(spec==null||spec=="")
            spec=key.getAlgorithm();
          try {
            Cipher ci=Cipher.getInstance(spec);
            ci.init(Cipher.DECRYPT_MODE, key);
            skey = (SecretKey)obj.getObject(ci);
          }
          catch (Exception e) {
            continue;
          }
        }

        if (skey == null) {
          // no key available to decrypt
          if (log.isWarnEnabled())
            log.warn("Cannot find a private key to decrypt Data Protection secret");
          continue;
        }

        if (log.isDebugEnabled()) {
          log.debug("Re-encrypting Data Protection secret key.");
        }
        List certList = keyRing.findCert(agent);
        if (certList == null || certList.size() == 0) {
          CertificateException cex = new CertificateException("Can not find agent cert: "+ agent);
          throw cex;
        }
        CertificateStatus cs = (CertificateStatus)certList.get(0);
        X509Certificate agentCert = (X509Certificate)cs.getCertificate();

        obj = encryptionService.asymmEncrypt(agent, spec, skey, agentCert);
        pke.setDataProtectionKey(
          new DataProtectionKeyImpl(obj, dpKey.getDigestAlg(), dpKey.getSecureMethod()));
      } catch (IOException ioe) {
      }
    }
  }

  public InputStream getInputStream(DataProtectionKeyEnvelope pke,
				    InputStream is)
	throws IOException, GeneralSecurityException
  {
    String agent = dpsClient.getAgentIdentifier().toAddress();

    if (log.isDebugEnabled())
      log.debug("getInputStream for " + agent);

    DataProtectionKeyImpl dpKey = (DataProtectionKeyImpl)pke.getDataProtectionKey();
    SecureMethodParam policy = dpKey.getSecureMethod();
    if (policy.secureMethod == SecureMethodParam.PLAIN)
      return is;

    // check if there is key and certificate created for the client
    List certList = keyRing.findCert(agent);
    if (certList == null || certList.size() == 0) {
      CertificateException cx = new CertificateException("No certificate available to sign.");
      publishDataFailure(agent, DataFailureEvent.NO_CERTIFICATES, cx.toString());
      throw cx;
    }
      /*
    String ofname = keyRing.getKeyStorePath();
    ofname = ofname.substring(0, ofname.lastIndexOf("/")) + "/" + agent + ".data";
    System.out.println("reading file: " + ofname);
    return new FileInputStream(new File(ofname));
    InputStream in = new DataProtectionInputStream(is, pke, agent, serviceBroker);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    byte [] bytes = new byte[2000];
    while (true) {
      int result = in.read(bytes);
      if (result == -1)
        break;
      bos.write(bytes, 0, result);
    }
    return new ByteArrayInputStream(bos.toByteArray());
	*/
	  DataProtectionInputStream dpis =
  	  new DataProtectionInputStream(is, pke, agent, serviceBroker);
    dpis.addPublisher(eventPublisher);
    return dpis;
  }

  public void release() {
    if (log.isDebugEnabled()) {
      log.debug("release data protection:"
		+ dpsClient.getAgentIdentifier().toAddress());
    }
  }

  /**
   * publish a data protection failure idmef alert
   */
  private void publishDataFailure(String agent, String reason, String data) {
    FailureEvent event = new DataFailureEvent(agent,
                                              agent,
                                              reason,
                                              data);
    if(eventPublisher != null) {
      eventPublisher.publishEvent(event);
    }
    else {
      if(log.isDebugEnabled()) {
        log.debug("EventPublisher uninitialized, unable to publish event:\n" + event);
      }
    }
  }
}
