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
import java.net.*;

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
import org.cougaar.core.security.policy.*;
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

    /*
    try {
      reprotectClient(dpsClient, null);
    } catch (GeneralSecurityException gsx) {
      if (log.isDebugEnabled())
        log.debug("Exception occured while reprotecting keys: " + gsx.toString());
    }
    */
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

    DataProtectionKeyCollection keyCollection =
      (DataProtectionKeyCollection)pke.getDataProtectionKey();
    if (keyCollection == null || keyCollection.size() == 0) {
      GeneralSecurityException gsx =
        new GeneralSecurityException("No data protection key present.");
      publishDataFailure(agent, DataFailureEvent.NO_KEYS, gsx.toString());
      throw gsx;
    }
    SecureMethodParam policy = ((DataProtectionKeyImpl)keyCollection.get(0)).getSecureMethod();
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
    //cps.getSendPolicy(agent, agent);
    CryptoPolicy cp = (CryptoPolicy)cps.getDataProtectionPolicy(agent);
    SecureMethodParam policy = cp.getSecureMethodParam(agent);

    if (policy == null) {
       RuntimeException rte = new RuntimeException("Could not find data protection policy for " + agent);
       publishDataFailure(agent, DataFailureEvent.INVALID_POLICY, rte.toString());
       throw rte;
    }
    else if (policy.secureMethod == SecureMethodParam.ENCRYPT
      || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      SecureRandom random = new SecureRandom();
      KeyGenerator kg = KeyGenerator.getInstance(keygenAlg);
      kg.init(random);
      SecretKey sk = kg.generateKey();
      List certlist = keyRing.findCert(agent);
      if (certlist == null || certlist.size() == 0) {
        throw new GeneralSecurityException("No certificate available for encrypting or signing.");
      }
      CertificateStatus cs = (CertificateStatus)certlist.get(0);
      X509Certificate agentCert = (X509Certificate)cs.getCertificate();

      SealedObject skeyobj = encryptionService.asymmEncrypt(agent,
        policy.asymmSpec, sk, agentCert);
      DataProtectionKeyImpl keyImpl =
	new DataProtectionKeyImpl(skeyobj, digestAlg, policy,
				  keyRing.findCertChain(agentCert));
      DataProtectionKeyCollection keyCollection =
	new DataProtectionKeyCollection();
      keyCollection.add(0, keyImpl);
      // Now, add keys of persistence manager agents (TODO)
      PersistenceManagerPolicy [] pmp = cp.getPersistenceManagerPolicies();
      if (pmp.length == 0) {
        if (log.isDebugEnabled()) {
          log.debug("No persistence manager policy available.");
        }
      }

      for (int i = 0; i < pmp.length; i++) {
        try {
          if (log.isDebugEnabled()) {
            log.debug("Encrypting secretkey with " + pmp[i].pmDN);
          }
          X500Name pmx500name = new X500Name(pmp[i].pmDN);
          String commonName = pmx500name.getCommonName();
          List certList = keyRing.findCert(commonName);
          if (certList == null || certList.size() == 0) {
            if (log.isWarnEnabled()) {
              log.warn("PersistenceManager cert not found: " + pmx500name);
            }
            continue;
          }
          cs = (CertificateStatus)certList.get(0);
          X509Certificate pmCert = cs.getCertificate();

          skeyobj = encryptionService.asymmEncrypt(commonName,
            policy.asymmSpec, sk, pmCert);
          DataProtectionKeyImpl pmDPKey =
        	new DataProtectionKeyImpl(skeyobj, digestAlg, policy,
				  keyRing.findCertChain(pmCert));
          keyCollection.add(pmDPKey);
        }
        catch (Exception iox) {
          if (log.isWarnEnabled()) {
            log.warn("Unable to get persistence manager: " + pmp[i].pmDN + " Reason: " + iox);
          }
        }
      }

      return keyCollection;
    }
    else {
      DataProtectionKeyImpl keyImpl =
	new DataProtectionKeyImpl(null, digestAlg, policy, null);
      DataProtectionKeyCollection keyCollection =
	new DataProtectionKeyCollection();
      keyCollection.add(0, keyImpl);
      return keyCollection;
    }
  }

  /**
   * This function is not doing anything because persistence is not providing
   * the iterator.
   */
   /*
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
        DataProtectionKeyEnvelope pke = (DataProtectionKeyEnvelope)
          keys.next();


    }
  }
  */

  private void reprotectClient(String agent, DataProtectionKeyEnvelope pke) {
      try {
        DataProtectionKeyCollection keyCollection = (DataProtectionKeyCollection)pke.getDataProtectionKey();

        if (keyCollection == null || keyCollection.size() == 0) {
          return;
	}
        CryptoPolicy cp = (CryptoPolicy)cps.getDataProtectionPolicy(agent);
        if (log.isDebugEnabled()) {
          log.debug("keyCollection size: " + keyCollection.size());
        }

        // the first one is the local agent encrypted key, the rest are
        // encrypted with persistent managers
        // check the first one's validity only
        DataProtectionKeyImpl dpKey = (DataProtectionKeyImpl)keyCollection.get(0);

        SecureMethodParam policy = dpKey.getSecureMethod();
        if (policy.secureMethod != SecureMethodParam.ENCRYPT
          && policy.secureMethod != SecureMethodParam.SIGNENCRYPT) {
          return;
        }

        // the original code repeats the same function but allows
        // expiration checking, there will be new function in
        // encryption service later on that enables decrypt using
        // expired certs
        SecretKey skey = (SecretKey)encryptionService.asymmDecrypt(
                          agent,
                          policy.asymmSpec,
                          (SealedObject)dpKey.getObject());

        /*
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
          String spec = policy.asymmSpec;
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
        */

	List certlist = keyRing.findCert(agent);
	CertificateStatus cs = (CertificateStatus)certlist.get(0);
	X509Certificate agentCert = (X509Certificate)cs.getCertificate();

        if (skey == null) {
          // no key available to decrypt
          if (log.isWarnEnabled())
            log.warn("Cannot find a private key to decrypt Data Protection secret."
              + " Try to get the secret from persistence manager for: " + agent);

          DataProtectionKeyUnlockRequest req =
            new DataProtectionKeyUnlockRequest(/*UID*/null,
                                              dpsClient.getAgentIdentifier(),
                                              /*target*/null,
                                              keyCollection,
                                              keyRing.findCertChain(agentCert));
          PersistenceManagerPolicy [] pmp = cp.getPersistenceManagerPolicies();
          // start the threads
          HttpRequestThread [] ts = new HttpRequestThread[pmp.length];
          for (int i = 0; i < pmp.length; i++) {
            ts[i] = new HttpRequestThread(req, pmp[i], agent);
            ts[i].start();
          }

          // timeout while checking results
          long timeout = 60000;
          while (skey == null && timeout > 0) {
            for (int i = 0; i < ts.length; i++) {
              if (ts[i]._skey != null) {
                skey = ts[i]._skey;
                break;
              }
            }
            Thread.currentThread().sleep(1000);
            timeout -= 1000;
            /*
            if (log.isDebugEnabled()) {
              log.debug("Time remaining: " + timeout);
            }
            */
          }

          if (skey == null) {
            if (log.isWarnEnabled()) {
              log.warn("Cannot recover secret key from persistence manager for: " + agent);
            }
            return;
          }
          else {
            if (log.isDebugEnabled()) {
              log.debug("Re-encrypting Data Protection secret key for: " + agent);
            }

            // reuse old signer if it exists
            X509Certificate oldSigner = dpKey.getOldSigner();

            SealedObject obj = (SealedObject)encryptionService.asymmEncrypt(agent,
                                                policy.asymmSpec, skey, agentCert);

            DataProtectionKeyImpl keyImpl =
              new DataProtectionKeyImpl(obj, digestAlg, policy,
                                        keyRing.findCertChain(agentCert));
            if (oldSigner == null) {
              X509Certificate [] oldCertChain = dpKey.getCertificateChain();
              if (oldCertChain == null || oldCertChain.length == 0) {
                if (log.isWarnEnabled()) {
                  log.warn("The old data protection key chain does not exist! "
                    + "Will not be able to verify signature.");
                }
              }

              else {
            // the old certificate will be used to verify signature
                oldSigner = oldCertChain[0];
              }
            }
            keyImpl.setOldSigner(oldSigner);
            if (log.isDebugEnabled()) {
              log.debug("using old cert to verify signature: " + oldSigner);
            }

            // replace the old key
            DataProtectionKeyCollection newCollection = new DataProtectionKeyCollection();
            newCollection.add(0, keyImpl);

            for (int i = 1; i < keyCollection.size(); i ++) {
              newCollection.add(keyCollection.get(i));
            }

            pke.setDataProtectionKey(newCollection);
          }
        }

      } catch (Exception ioe) {
	if (log.isWarnEnabled()) {
	  log.warn("Unable to reprotect client key: ", ioe);
	}
      }
  }

  class HttpRequestThread extends Thread {
    SecretKey _skey;
    DataProtectionKeyUnlockRequest _req;
    PersistenceManagerPolicy _pmp;
    String _agent;

    HttpRequestThread(DataProtectionKeyUnlockRequest req,
                      PersistenceManagerPolicy pmp,
                      String agent) {
      _req = req;
      _pmp = pmp;
      _agent = agent;
    }

    public void run() {
      try {
        if (log.isDebugEnabled()) {
          log.debug("Sending recovery msg to " + _pmp.pmUrl);
        }

        URL url = new URL(_pmp.pmUrl);
        HttpURLConnection huc = (HttpURLConnection)url.openConnection();
        // Don't follow redirects automatically.
        huc.setInstanceFollowRedirects(false);
        // Let the system know that we want to do output
        huc.setDoOutput(true);
        // Let the system know that we want to do input
        huc.setDoInput(true);
        // No caching, we want the real thing
        huc.setUseCaches(false);
        // Specify the content type
        huc.setRequestProperty("Content-Type",
                               "application/x-www-form-urlencoded");
        huc.setRequestMethod("POST");
        ObjectOutputStream out = new ObjectOutputStream(huc.getOutputStream());
        out.writeObject(_req);

        out.flush();
        out.close();

        ObjectInputStream in = new ObjectInputStream(huc.getInputStream());
        _req = (DataProtectionKeyUnlockRequest)in.readObject();
        in.close();

        DataProtectionKeyImpl newKey = (DataProtectionKeyImpl)_req.getResponse();
        if (newKey != null) {
          SealedObject responseObj = (SealedObject)newKey.getObject();
          if (responseObj != null) {
            _skey = (SecretKey)encryptionService.asymmDecrypt(
                          _agent,
                          newKey.getSecureMethod().asymmSpec,
                          responseObj);
            if (log.isDebugEnabled()) {
              log.debug("Secretkey recovered from " + _pmp.pmDN);
            }
          }
        }
        else {
          if (log.isDebugEnabled()) {
            log.debug("Persistence manager returns with no response.");
          }
        }

      } catch(Exception e) {
        log.warn("Unable to send keyUnlock request to persistence manager.", e);
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

    reprotectClient(agent, pke);

    DataProtectionKeyCollection keyCollection =
      (DataProtectionKeyCollection)pke.getDataProtectionKey();
    if (keyCollection == null || keyCollection.size() == 0) {
      GeneralSecurityException gsx =
        new GeneralSecurityException("No data protection key present.");
      publishDataFailure(agent, DataFailureEvent.NO_KEYS, gsx.toString());
      throw gsx;
    }

    DataProtectionKeyImpl dpKey = (DataProtectionKeyImpl)keyCollection.get(0);
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
