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


package org.cougaar.core.security.dataprotection;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import javax.crypto.SecretKey;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertificateRevokedException;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.SecureMethodParam;
import org.cougaar.core.security.monitoring.event.DataFailureEvent;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.publisher.SecurityEventPublisher;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.CryptoPolicy;
import org.cougaar.core.security.policy.PersistenceManagerPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.PersistenceMgrAvailListener;
import org.cougaar.core.security.services.util.PersistenceMgrPolicyService;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.service.DataProtectionKey;
import org.cougaar.core.service.DataProtectionKeyEnvelope;
import org.cougaar.core.service.DataProtectionService;
import org.cougaar.core.service.DataProtectionServiceClient;
import org.cougaar.core.service.LoggingService;

import sun.security.x509.X500Name;


public class DataProtectionServiceImpl
  implements DataProtectionService, PersistenceMgrAvailListener, BlackboardClient
{
  private ServiceBroker serviceBroker;
  private EncryptionService encryptionService;
  private CryptoPolicyService cps;
  private KeyRingService keyRing;
  private LoggingService log;
  private DataProtectionServiceClient dpsClient;
  // service used to obtain the persistence manager policies
  private PersistenceMgrPolicyService pps;
  //private String keygenAlg = "AES";
  private String digestAlg = "SHA";
  private CryptoClientPolicy cryptoClientPolicy;
  private String agent=null;
  
  // event publisher for data protection failures
  //private static EventPublisher eventPublisher;
  private Hashtable keyCache = new Hashtable();

  final static String CERT_POLL_TIME = "org.cougaar.core.security.certpoll";
  final static String CERT_POLL_SLICE = "org.cougaar.core.security.certpollslice";

  /*
  // add event publisher
  public static void addPublisher(EventPublisher publisher) {
    if(eventPublisher == null) {
      eventPublisher = publisher;
    }
  }
  */

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
    // Get the PersistenceMgrPolicyService
    pps = (PersistenceMgrPolicyService)
      serviceBroker.getService(requestor,
                               PersistenceMgrPolicyService.class,
                               null);

    ConfigParserService configParser = (ConfigParserService)
      serviceBroker.getService(this,
					    ConfigParserService.class,
					    null);
    SecurityPolicy[] sp =
      configParser.getSecurityPolicies(CryptoClientPolicy.class);
    cryptoClientPolicy = (CryptoClientPolicy) sp[0];

    if (encryptionService == null) {
       throw new RuntimeException("Encryption service not available");
    }
    if (cps == null) {
       throw new RuntimeException("Policy service not available");
    }
    if (keyRing == null) {
       throw new RuntimeException("KeyRing service not available");
    }
    if (pps == null) {
      throw new RuntimeException("PersistenceMgrPolicy service not available");
    }
    if (!(requestor instanceof DataProtectionServiceClient)) {
      throw new RuntimeException("Requestor is not DataProtectionServiceClient");
    }
    dpsClient = (DataProtectionServiceClient)requestor;

    // add listener to new persistence manager coming up
    agent = dpsClient.getAgentIdentifier().toAddress();
    if (!cryptoClientPolicy.isCertificateAuthority()
      && !agent.equals(NodeInfo.getNodeName())) {
      pps.addPMListener(dpsClient.getAgentIdentifier().toAddress(), this);
    }
  }
  
	
  public void newPMAvailable(PersistenceManagerPolicy pmp) {
    if (log.isDebugEnabled()) {
      log.debug("Reprotect with " + keyCache.size() + " entries with " + pmp.pmDN);
    }

    final String agent = dpsClient.getAgentIdentifier().toAddress();

    for (Enumeration it = keyCache.keys(); it.hasMoreElements(); ) {
      try {
        SecretKey skey = (SecretKey)it.nextElement();
        DataProtectionKeyEnvelope pke =
          (DataProtectionKeyEnvelope)keyCache.get(skey);
        DataProtectionKeyCollection keyCollection =
          (DataProtectionKeyCollection)pke.getDataProtectionKey();

        protectWithPM(pmp, skey, keyCollection);
        pke.setDataProtectionKey(keyCollection);

        String sendSignature = System.getProperty("org.cougaar.core.security.dataprotection.sendSignature", "true");
        if (sendSignature.equals("true")) {
          if (keyCollection.getSignature() == null) {
            log.warn("No signature found to send to PM for compromise recovery");
            return;
          }

          if (log.isDebugEnabled()) {
            log.debug("trying to send session key using relay " + agent + " at time " + keyCollection.getTimestamp());
          }
   
          String pmName = null;
          try {
            pmName = new X500Name(pmp.pmDN).getCommonName();
          }
          catch (IOException iox) {
            if (log.isWarnEnabled()) {
              log.warn("Failed to get common name for PM cert: " + pmp.pmDN);
              return;
            }
          }
          SessionKeySenderPlugin.sendSessionKey(agent, keyCollection, pmName);
        }
      } catch (IOException iox) {
        log.warn("Reprotect secret key failed!", iox);
      }
    }
  }

  public OutputStream getOutputStream(DataProtectionKeyEnvelope pke,
				      OutputStream os)
	throws IOException
  {

    final String agent = dpsClient.getAgentIdentifier().toAddress();

    if (log.isDebugEnabled()) {
      log.debug("getOutputStream for " + agent);
    }
    
    // check if there is key and certificate created for the client
    List certList = null;

    /*
    if (certList == null || certList.size() == 0) {
      int totalWait = 240000; // the persistence wait time is 4 minutes, so that we don't block the next persistence
                              // which will also fail anyway
      int wait_time = 10000;
      try {
        totalWait = Integer.parseInt(System.getProperty(CERT_POLL_TIME,
          new Integer(totalWait).toString()));
        wait_time = Integer.parseInt(System.getProperty(CERT_POLL_SLICE,
          new Integer(wait_time).toString()));
      } catch (Exception nx) {
      }
      while ((certList = keyRing.findCert(agent, KeyRingService.LOOKUP_KEYSTORE)) == null || certList.size() == 0) {
        totalWait -= wait_time;
        if (totalWait <= 0) {
          break;
        }
        if (log.isDebugEnabled()) {
          log.debug("no certificate found, waiting ...");
        }
        try {
          Thread.currentThread().sleep(wait_time);
        }
        catch (Exception ex) {}
      }
    }
    */
    certList = keyRing.findCert(agent, KeyRingService.LOOKUP_KEYSTORE);
    if (certList == null || certList.size() == 0) {
      CertificateException cx = new CertificateException("No certificate available to sign.");
      publishDataFailure(agent, DataFailureEvent.NO_CERTIFICATES, cx.toString());
      throw new IOException(cx.getMessage());
    }
    DataProtectionKey dpKey = null;
    try {
      dpKey = pke.getDataProtectionKey();
    }
    catch (Exception ioe) {
      if (log.isDebugEnabled()) {
        log.debug("Unable to get data protection key:" + ioe);
      }
    }
    if (dpKey == null) {
      try {
        dpKey = createDataProtectionKey(agent,pke);
      }
      catch(GeneralSecurityException gsx) {
        publishDataFailure(agent, DataFailureEvent.CREATE_KEY_FAILURE, gsx.toString());
	IOException e = new IOException(gsx.getMessage());
	e.initCause(gsx);
        throw e;
	
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
      throw new IOException(gsx.getMessage());
    }
    SecureMethodParam policy = ((DataProtectionKeyImpl)keyCollection.get(0)).getSecureMethod();
    if (policy.secureMethod == SecureMethodParam.PLAIN)
      return os;

    // check whether key needs to be replaced
    try {
      DataProtectionOutputStream dpos =
        new DataProtectionOutputStream(os, pke, agent, serviceBroker);
      //dpos.addPublisher(eventPublisher);
      return dpos;
    } catch (GeneralSecurityException gsx) {
      throw new IOException(gsx.getMessage());
    }
  }

  private DataProtectionKey createDataProtectionKey(String agent, DataProtectionKeyEnvelope pke)
    throws GeneralSecurityException, IOException {
    //SecureMethodParam policy =
    //cps.getSendPolicy(agent, agent);
    CryptoPolicy cp = (CryptoPolicy)cps.getDataProtectionPolicy(agent);
    if (cp == null) {
      String err = "Unable to get Data Protection policy for " + agent;
      log.error(err);
      throw new RuntimeException(err);
    }
    SecureMethodParam policy = cp.getSecureMethodParam(agent);

    if (policy == null) {
       RuntimeException rte = new RuntimeException("Could not find data protection policy for " + agent);
       publishDataFailure(agent, DataFailureEvent.INVALID_POLICY, rte.toString());
       throw rte;
    }
    else if (policy.secureMethod == SecureMethodParam.ENCRYPT
      || policy.secureMethod == SecureMethodParam.SIGNENCRYPT) {
      SecretKey sk = encryptionService.createSecretKey(policy.symmSpec);
      List certlist = keyRing.findCert(agent, KeyRingService.LOOKUP_KEYSTORE);
      if (certlist == null || certlist.size() == 0) {
        throw new GeneralSecurityException("No certificate available for encrypting or signing.");
      }
      CertificateStatus cs = (CertificateStatus)certlist.get(0);
      X509Certificate agentCert = (X509Certificate)cs.getCertificate();

      byte[] skeyobj = encryptionService.encryptSecretKey(
        policy.asymmSpec, sk, agentCert);
      DataProtectionKeyImpl keyImpl =
	new DataProtectionKeyImpl(skeyobj, digestAlg, policy,
				  keyRing.findCertChain(agentCert));
      DataProtectionKeyCollection keyCollection =
	new DataProtectionKeyCollection();
      keyCollection.add(0, keyImpl);

      // if CA no need to worry about recovery, a new CA should be started
      // no need to recover for node
      if (cryptoClientPolicy.isCertificateAuthority()
        || agent.equals(NodeInfo.getNodeName())) {
        return keyCollection;
      }

      // Now, add keys of persistence manager agents (TODO)
      // PersistenceManagerPolicy [] pmp = cp.getPersistenceManagerPolicies();
      // wait for at least one pm to start
      PersistenceManagerPolicy [] pmp = pps.getPolicies();

      if (log.isDebugEnabled()) {
        log.debug("Protecting " + agent + " with " + pmp.length + " managers.");
      }

      for (int i = 0; i < pmp.length; i++) {
        if (log.isDebugEnabled()) {
          log.debug("Protecting " + agent + " with " + pmp[i].pmDN);
        }
        protectWithPM(pmp[i], sk, keyCollection);
      }

      // add a listener to the new managers available
      // cache secret key and keycollection, protect with the newly
      // available PM, and save it (does the set method actually
      // saves when called?)
      keyCache.put(sk, pke);

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

  private DataProtectionKeyCollection protectWithPM(PersistenceManagerPolicy pmp,
    SecretKey sk, DataProtectionKeyCollection keyCollection) {
    if (log.isDebugEnabled()) {
      log.debug("Encrypting secretkey with " + pmp.pmDN);
    }
    try {
      // get the first entry to get the dp policy
      DataProtectionKeyImpl dpKey = (DataProtectionKeyImpl)keyCollection.get(0);
      SecureMethodParam policy = dpKey.getSecureMethod();

      X500Name pmx500name = new X500Name(pmp.pmDN);
      //String commonName = pmx500name.getCommonName();
      // find cert with common name does not return the certs from
      // peer, it only returns all the cert locally
      List certList = keyRing.findCert(pmx500name,
       KeyRingService.LOOKUP_KEYSTORE | KeyRingService.LOOKUP_LDAP, true);
      if (certList == null || certList.size() == 0) {
        if (log.isWarnEnabled()) {
          log.warn("PersistenceManager cert not found: " + pmx500name);
        }
        return keyCollection;
      }
      CertificateStatus cs = (CertificateStatus)certList.get(0);
      X509Certificate pmCert = cs.getCertificate();

      byte[] skeyobj = encryptionService.encryptSecretKey(
        policy.asymmSpec, sk, pmCert);
      DataProtectionKeyImpl pmDPKey =
            new DataProtectionKeyImpl(skeyobj, digestAlg, policy,
                              keyRing.findCertChain(pmCert), pmp);
//	TODO Is this the right place for this?
/*
	if(log.isDebugEnabled()){
		log.debug("trying to send session key using relay");
	}
	RelaySessionKey.getInstance().relaySessionKey(keyCollection,commonName, agent);
*/
	
      keyCollection.add(pmDPKey);
    }
    catch (Exception iox) {
      if (log.isWarnEnabled()) {
        log.warn("Unable to get persistence manager: " + pmp.pmDN + " Reason: " + iox);
      }
    }

    return keyCollection;
  }

  private void reprotectClient(String agent, DataProtectionKeyEnvelope pke) {
      try {
        DataProtectionKeyCollection keyCollection = (DataProtectionKeyCollection)pke.getDataProtectionKey();

        if (keyCollection == null || keyCollection.size() == 0) {
          return;
        }
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


	List certList = keyRing.findCert(agent, KeyRingService.LOOKUP_KEYSTORE, true);
        if (certList == null || certList.size() == 0) {
/*
          int totalWait = 400000; // the persistence time is 5 minutes
          int wait_time = 10000;
          try {
            totalWait = Integer.parseInt(System.getProperty(CERT_POLL_TIME,
              new Integer(totalWait).toString()));
            wait_time = Integer.parseInt(System.getProperty(CERT_POLL_SLICE,
              new Integer(wait_time).toString()));
          } catch (Exception nx) {
          }
          while ((certList = keyRing.findCert(agent, KeyRingService.LOOKUP_KEYSTORE)) == null || certList.size() == 0) {
            totalWait -= wait_time;
            if (totalWait <= 0) {
              break;
            }
            if (log.isDebugEnabled()) {
              log.debug("no certificate found, waiting ...");
            }
            try {
              Thread.currentThread().sleep(wait_time);
            }
            catch (Exception ex) {}
          }
*/
        // a heck to get agent certificate 
        // persistence rehydration is started before agent identity so
        // we will never get the agent cert here
          keyRing.checkOrMakeCert(agent);
          certList = keyRing.findCert(agent, KeyRingService.LOOKUP_KEYSTORE);
        }
        
        if (certList == null || certList.size() == 0) {
          CertificateException cx = new CertificateException("No certificate available to sign.");
          publishDataFailure(agent, DataFailureEvent.NO_CERTIFICATES, cx.toString());
          throw new IOException(cx.getMessage());
        }

	CertificateStatus cs = (CertificateStatus)certList.get(0);
	X509Certificate agentCert = (X509Certificate)cs.getCertificate();

        if (agentCert == null) {
	  throw new Exception("Cannot find a certificate from keystore to reprotect secret key.");
        }


        // the original code repeats the same function but allows
        // expiration checking, there will be new function in
        // encryption service later on that enables decrypt using
        // expired certs
        SecretKey skey = null;
        try {
          skey = encryptionService.decryptSecretKey(
                          policy.asymmSpec,
                          (byte[])dpKey.getObject(),
                          policy.symmSpec,
                          dpKey.getCertificateChain()[0]);
        } catch (GeneralSecurityException gse) {
          if (log.isDebugEnabled()) {
            log.debug("Unable to decrypt key:" + gse);
          }
        }

        if (skey == null) {
          if (keyCollection.size() == 1) {
            log.error("Cannot recover key for; " + dpsClient.getAgentIdentifier()
              + ", the key is not encrypted with any persistence manager.");
            return;
          }

          // check certificate expiry
    X509Certificate[] originalCertChain = dpKey.getCertificateChain();
    if ((originalCertChain == null) || (originalCertChain.length == 0)) {
      if (log.isWarnEnabled()) {
        log.warn("secret key collection for " + agent + " contains no certificate chain for the original agent");
      }

      return;
    }

    X509Certificate originalAgentCert = originalCertChain[0];
    try {
      keyRing.checkCertificateTrust(originalAgentCert);
    } catch (Exception e) {
    boolean digestVerify = false;

    String sendSignature = System.getProperty("org.cougaar.core.security.dataprotection.sendSignature", "true");
    digestVerify = sendSignature.equals("true");

      String msg = "Recovery failure: certificate protecting secret key is not trusted for " + agent + ". " + e.toString();
      if (!(e instanceof CertificateRevokedException) || !digestVerify) {
          CertificateException cx = new CertificateException(msg);
          publishDataFailure(agent, DataFailureEvent.NO_CERTIFICATES, cx.toString());
          throw new IOException(cx.getMessage());
      }
      else {
        if (log.isDebugEnabled()) {
          log.debug("Agent " + agent + " is revoked, sending it to PM for recovery.");
        }
      }
    }       

          // no key available to decrypt
          if (log.isDebugEnabled())
            log.debug("Cannot find a private key to decrypt Data Protection secret."
              + " Try to get the secret from persistence manager for: " + agent);

          DataProtectionKeyUnlockRequest req =
            new DataProtectionKeyUnlockRequest(/*UID*/null,
                                              dpsClient.getAgentIdentifier(),
                                              /*target*/null,
                                              keyCollection,
                                              keyRing.findCertChain(agentCert));

          Hashtable pmNames = new Hashtable();
          for (int idn = 1; idn < keyCollection.size(); idn++) {
            DataProtectionKeyImpl pmkey = (DataProtectionKeyImpl)keyCollection.get(idn);
            String pmName = pmkey.getCertificateChain()[0].getSubjectDN().getName();
            try {
              pmNames.put(new X500Name(pmName).getCommonName(), pmName);
              if (log.isDebugEnabled()) {
                log.debug("secret key is encrypted with " + pmName);
              }
            } catch (IOException iox) {
              log.warn("Invalid PM encrypted: " + pmName);
            }
          }

          //PersistenceManagerPolicy [] pmp = cp.getPersistenceManagerPolicies();
          // wait for 20 minutes
          int wait_time = 1200000;
          try {
            int configwait = Integer.parseInt(System.getProperty("org.cougaar.core.security.recoverytime", Integer.toString(wait_time)));
            wait_time = configwait;
          } catch (Exception tex) {
            if (log.isWarnEnabled()) {
              log.warn("Unable to parse org.cougaar.core.security.recoverytime property: " + tex);
            }
          }

          int sleep_time = 10000;
          while (skey == null && wait_time > 0) {
            PersistenceManagerPolicy [] pmp = pps.getPolicies();
            if (pmp.length == 0 && keyCollection.size() > 1) {
              pmp = new PersistenceManagerPolicy[keyCollection.size() - 1];
              for (int i = 1; i < keyCollection.size(); i++) {
                DataProtectionKeyImpl keyImpl = (DataProtectionKeyImpl)
                  keyCollection.get(i);
                pmp[i-1] = keyImpl.getPMPolicy();
              }
            }

            if (log.isDebugEnabled()) {
              log.debug("pmp size: " + pmp.length);
            }

            for (int i = 0; i < pmp.length; i++) {
              // did we use the pm cert to encrypt the secret key at all?
/*
              try {
                X500Name pmx500 = new X500Name(pmp[i].pmDN);
                if (pmNames.get(pmx500.getCommonName()) != null) {
*/
                  skey = requestPersistenceRecovery(req, pmp[i], agent);
/*
                }
              } catch (IOException iox) {
                log.warn("Invalid pm: " + pmp[i].pmDN);
                continue;
              }
*/

              if (skey != null) {
                break;
              }
            }
            Thread.sleep(sleep_time);
            wait_time -= sleep_time;
          }

          // need to give up if still no key
          if (skey == null) {
            throw new Exception("Cannot recover secret key for " + agent);
          }

            if (log.isDebugEnabled()) {
              log.debug("Re-encrypting Data Protection secret key for: " + agent);
            }

            // reuse old signer if it exists
            X509Certificate oldSigner = dpKey.getOldSigner();

            byte[] obj = encryptionService.encryptSecretKey(
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

      } catch (Exception ioe) {
	if (log.isWarnEnabled()) {
	  log.warn("Unable to reprotect client key: ", ioe);
	}
      }
  }

  SecretKey requestPersistenceRecovery(DataProtectionKeyUnlockRequest _req,
                      PersistenceManagerPolicy _pmp,
                      String _agent) {
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
          byte[] responseObj = (byte[])newKey.getObject();
          if (responseObj != null) {
            SecretKey skey = encryptionService.decryptSecretKey(
                          newKey.getSecureMethod().asymmSpec,
                          responseObj,
			  newKey.getSecureMethod().symmSpec,
			  newKey.getCertificateChain()[0]);
            if (skey != null) {
              if (log.isDebugEnabled()) {
                log.debug("Secretkey recovered from " + _pmp.pmDN);
              }
            }
            return skey;
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
    return null;
  }

  public InputStream getInputStream(DataProtectionKeyEnvelope pke,
				    InputStream is)
	throws IOException
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
      throw new IOException(gsx.getMessage());
    }

    DataProtectionKeyImpl dpKey = (DataProtectionKeyImpl)keyCollection.get(0);
    SecureMethodParam policy = dpKey.getSecureMethod();
    if (policy.secureMethod == SecureMethodParam.PLAIN)
      return is;

    // check if there is key and certificate created for the client
    List certList = keyRing.findCert(agent, KeyRingService.LOOKUP_KEYSTORE);
    if (certList == null || certList.size() == 0) {
      CertificateException cx = new CertificateException("No certificate available to sign.");
      publishDataFailure(agent, DataFailureEvent.NO_CERTIFICATES, cx.toString());
      throw new IOException(cx.getMessage());
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
    try {
      DataProtectionInputStream dpis =
        new DataProtectionInputStream(is, pke, agent, serviceBroker);
    //dpis.addPublisher(eventPublisher);
      return dpis;
    } catch (GeneralSecurityException gsx) {
      throw new IOException(gsx.getMessage());
    }
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
    /*
    if(eventPublisher != null) {
      eventPublisher.publishEvent(event);
    }
    else {
      if(log.isDebugEnabled()) {
        log.debug("EventPublisher uninitialized, unable to publish event:\n" + event);
      }
    }
    */
    SecurityEventPublisher.publishEvent(event);
  }

	/* (non-Javadoc)
	 * @see org.cougaar.core.blackboard.BlackboardClient#getBlackboardClientName()
	 */
	public String getBlackboardClientName() {
		return this.getClass().getName();
	}

	/* (non-Javadoc)
	 * @see org.cougaar.core.blackboard.BlackboardClient#currentTimeMillis()
	 */
	public long currentTimeMillis() {
		return System.currentTimeMillis();
	}
}
