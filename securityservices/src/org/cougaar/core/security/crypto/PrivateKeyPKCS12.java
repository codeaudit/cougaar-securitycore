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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.service.LoggingService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

import com.ibm.security.pkcs12.PKCS12PFX;
import com.ibm.security.pkcs8.PrivateKeyInfo;
import com.ibm.security.pkcsutil.PKCSException;


public class PrivateKeyPKCS12
{
  // private DirectoryKeyStore directory = null;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  public PrivateKeyPKCS12(ServiceBroker sb)
    {
      //directory = aDirectory;
      serviceBroker = sb;
      log = (LoggingService)
	serviceBroker.getService(this,
				 LoggingService.class, null);
    }

  
  /** @param privKey        The private keys to store in a PKCS#12 enveloppe
   *  @param cert           The certificate to store in a PKCS#12 enveloppe
   *  @param signerPrivKey  The private key of the signer
   *  @param signerCert     The certificate of the signer
   *  @param rcvrCert       The certificate of the intended receiver
   */
  public byte[] protectPrivateKey(List privKey,
				  List cert,
				  PrivateKey signerPrivKey,
				  Certificate signerCert,
				  Certificate rcvrCert)
    {
      /* 
       * Create an array of certificates.  The certificates in the array 
       * belong to each intended receiver of the private information. 
       */
      if (log.isDebugEnabled()) {
	log.debug("Creating array of receiver certificates");
      }
      Certificate[] rcvrCerts = new Certificate[1];
      rcvrCerts[0] = rcvrCert;

      /* 
       * Create an empty PKCS12PFX to which the data items will be added.
       */
      if (log.isDebugEnabled()) {
	log.debug("Creating an empty PKCS12PFX");
      }
      PKCS12PFX pfx = new PKCS12PFX();
       
      /* 
       * Data in a PKCS12PFX need not have any attached attributes.  That is, 
       * neither friendly names nor local key ids are required as per the 
       * standard.  Data in PKCS12PFXs is packaged into a "bag" which is a 
       * bundling of the data and its attributes (if any), all optionally 
       * protected.
     
       /*
       * Add the personal information. Data privacy will be ensured through 
       * public-key protection.  
       * A piece of private information (represented by an input object)
       * is added to the PFX. The information will be protected with
       * public-key privacy.
       */
      try {
	if (log.isDebugEnabled()) {
	  log.debug("Adding certificate to the PFX");
	}
	Iterator it = cert.iterator();
	while (it.hasNext()) {
	  X509Certificate c = ((CertificateStatus)it.next()).getCertificate();
	  pfx.addBagWithPubkeyPrivacy(c, null, rcvrCerts);
	}

	if (log.isDebugEnabled()) {
	  log.debug("Adding signer certificate to the PFX");
	}
	pfx.addBagWithPubkeyPrivacy(signerCert, null, rcvrCerts);

	if (log.isDebugEnabled()) {
	  log.debug("Adding private key to the PFX");
	}
	it = privKey.iterator();
	while (it.hasNext()) {
	  PrivateKeyCert pkc = (PrivateKeyCert)it.next();
	  PrivateKey key = pkc.getPrivateKey();
	  try {
	    com.ibm.security.x509.AlgorithmId algid =
	      com.ibm.security.x509.AlgorithmId.get(key.getAlgorithm());
	    PrivateKeyInfo pkinfo = new PrivateKeyInfo(algid, key.getEncoded(), null);
	    pfx.addBagWithPubkeyPrivacy(pkinfo, null, rcvrCerts);
	  } catch (java.security.NoSuchAlgorithmException ex) {
	    if (log.isDebugEnabled()) {
	      log.debug("Error: " + ex);
	    }
	    return null;
	  }
	}
      } catch (PKCSException e) {
	if (log.isDebugEnabled()) {
	  log.debug("Error adding data to the PFX.");
	  log.debug("Original Exception:");
	  e.getRelatedException().printStackTrace();
	}
	return null;
      } catch (IOException e2) {
	log.debug("Error adding data to the PFX.");
	e2.printStackTrace();
	return null;
      }

      /* Add the certificate of the signer, so that the receiver can
       * verify the signature.
       */
      try {
	if (log.isDebugEnabled()) {
	  log.debug("Adding clear-text signer certificate to the PFX");
	}
	pfx.addBag(signerCert, null);
      } catch (PKCSException e) {
	if (log.isDebugEnabled()) {
	  log.debug("Error adding signer certificate to the PFX.");
	  log.debug("Original Exception:");
	  e.getRelatedException().printStackTrace();
	}
	return null;
      } catch (IOException e2) {
	if (log.isDebugEnabled()) {
	  log.debug("Error adding signer certificate to the PFX.");
	  e2.printStackTrace();
	}
	return null;
      }
      /* 
       * Ensure data integrity by applying a digital signature to the PFX.  
       * Specify a digest and encryption algorithm for the signature, as well
       * as the signer's certificate and private key.  Valid values for the 
       * encryption algorithm are RSA (when using RSA keys) and DSA (when 
       * using DSA keys).  Valid digest algorithms are SHA1, MD2 and MD5 
       * (when using RSA) and SHA1 (when using DSA).
       */
      if (log.isDebugEnabled()) {
	log.debug("Applying a digital signature to the PFX");
      }
      try {
	pfx.applySignature("SHA1", "RSA", signerCert, signerPrivKey);
      } catch (PKCSException e) {
	if (log.isDebugEnabled()) {
	  log.debug("Error protecting PFX.");
	  log.debug("Original Exception:");
	  e.getRelatedException().printStackTrace();
	  log.debug("PKCSException:");
	  e.printStackTrace();
	}
	return null;
      } catch (IOException e2) {
	if (log.isDebugEnabled()) {
	  log.debug("Error protecting PFX.");
	  e2.printStackTrace();
	}
	return null;
      } catch (NoSuchAlgorithmException e3) {
	if (log.isDebugEnabled()) {
	  log.debug("An HMAC algorithm is not supported");
	  e3.printStackTrace();
	}
	return null;
      }
    
      ByteArrayOutputStream ba = new ByteArrayOutputStream();
      try {
	pfx.encode(ba);
      } catch (IOException e2) {
	if (log.isDebugEnabled()) {
	  log.debug("Unable to encode PFX.");
	  e2.printStackTrace();
	}
	return null;
      }
   
      return ba.toByteArray();
    }

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private keys of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  public PrivateKeyCert[] getPfx(byte[] pfxBytes,
				 List rcvrPrivKeyList,
				 List rcvrCertList)
    {
      PKCS12PFX pfx = new PKCS12PFX();
      Certificate[] certs = null;
      PrivateKey[] keys = null;
      PrivateKeyCert[] keypairs = null;

      KeyRingService keyRing=(KeyRingService)
	serviceBroker.getService(this,
				 KeyRingService.class,
				 null);

      // TODO: try all keys
      PrivateKey rcvrPrivKey = ((PrivateKeyCert)rcvrPrivKeyList.get(0)).getPrivateKey();
      X509Certificate rcvrCert = ((CertificateStatus)rcvrCertList.get(0)).getCertificate();

      /* 
       * Construct a PFX from its DER-encoding. In this PFX, public
       * key mode was used to protect data privacy and ensure data integrity. 
       */
      try {
	if (log.isDebugEnabled()) {
	  log.debug("Creating PKCS12 envelope from DER encoded value");
	}
	pfx = new PKCS12PFX(pfxBytes);
      } catch (IOException e) {
	if (log.isDebugEnabled()) {
	  log.debug("Cannot create PFX from DER-encoding."); 
	  e.printStackTrace();
	  return keypairs;
	}
      }
     
      /* Extract the signer's certificate
       */
      Certificate[] signerCerts = null;
      try {
	// There should be only one certificate.
	signerCerts = pfx.getAllCertificates(null, null, null);
      } catch (PKCSException e) {
	if (log.isDebugEnabled()) {
	  log.debug("Error retrieving signer certificate from PFX.");
	  log.debug("Original Exception:");
	  e.getRelatedException().printStackTrace();
	  log.debug("PKCSException:");
	  e.printStackTrace();
	  return keypairs;
	}
      } catch (IOException e2) {
	if (log.isDebugEnabled()) {
	  log.debug("Error retrieving signer certificate from PFX.");
	  e2.printStackTrace();
	  return keypairs;
	}
      }
      if(log.isDebugEnabled()) {
	log.debug("The PKCS12 envelope contains "
		  + ((signerCerts != null) ? signerCerts.length : 0)
		  + " unprotected certificates");
      }
      if (signerCerts == null || signerCerts.length != 1) {
	if (log.isDebugEnabled()) {
	  log.debug("Unable to retrieve signer certificate");
	}
	return keypairs;
      }
      Certificate signerCert = signerCerts[0];

      /* Check the trust of the signer certificate.
       */
      if (log.isDebugEnabled()) {
	log.debug("Checking signer certificate trust for "
		  + signerCert.toString());
      }
      X509Certificate[] signerCertChain = null;
    
      if(keyRing!=null) {
	try {
	  signerCertChain =keyRing.checkCertificateTrust((X509Certificate)signerCert);
	}
	catch (Exception e) {
	  if (log.isDebugEnabled()) {
	    log.debug("Warning: Signer Certificate is not trusted" + e);
	  }
	  return keypairs;
	}
      }
      else {
	if (log.isDebugEnabled()) {
	  log.debug("Unable to check trust as KerRing Service is null  ");
	}
      }
    
      /*
       * Verify the digital signature to be sure that the data has not been 
       * tampered with.  You must use the public key corresponding to the 
       * private key that signed the PFX.  This public key is usually found
       * within a certificate.
       */
      if (log.isDebugEnabled()) {
	log.debug("Verifying the PFX digital signature");
      }
      try {
	if (pfx.verifySignature(signerCert)) {
	  if (log.isDebugEnabled()) {
	    log.debug("The PFX data is verified");
	  }
	} else {
	  if (log.isDebugEnabled()) {
	    log.debug("The PFX data is not verified");
	  }
	  return keypairs;
	}
      } catch (PKCSException e) {
	if (log.isDebugEnabled()) {
	  log.debug("Error verifying signature.");
	  log.debug("Original Exception:");
	  e.getRelatedException().printStackTrace();
	  log.debug("PKCSException:");
	  e.printStackTrace();
	}
	return keypairs;
      } catch (NoSuchAlgorithmException e2) {
	if (log.isDebugEnabled()) {
	  log.debug("Unsupported signature algorithm.");
	  e2.printStackTrace();
	}
	return keypairs;
      } catch (IOException e3) {
	if (log.isDebugEnabled()) {
	  log.debug("IOException verifying signature.");
	  e3.printStackTrace();
	}
	return keypairs;
      }

      /* 
       * Extract personal data from the PFX. Data accessible with the input 
       * certificate and private key will be retrieved.  If it is known that 
       * the data is accessible with different certificates and keys, 
       * additional get* method calls with the different arguments should be 
       * made.  The get* methods will not return unprotected data.
       */
    
      /* 
       * Attempt to get certificates using a good certificate and private key.
       */
      if (log.isDebugEnabled()) {
	log.debug("Extracting certificates");
      }
      try {
	certs = pfx.getAllCertificates(null, rcvrPrivKey, rcvrCert);
	if ((certs == null) || (certs.length == 0)) {
	  if (log.isDebugEnabled()) {
	    log.debug("Got no certificates");
	  }
	  return keypairs;
	} else {
	  if (log.isDebugEnabled()) {
	    log.debug("Got " + certs.length + " certificates");
	    for (int i = 0 ; i < certs.length ; i++) {
	      log.debug("Certificate[" + i + "]="
			+ certs[i]);
	    }
	  }
	}
      } catch (PKCSException e) {
	if (log.isDebugEnabled()) {
	  log.debug("Error extracting certificates from PFX.");
	  log.debug("Original Exception:");
	  e.getRelatedException().printStackTrace();
	  log.debug("PKCSException:");
	  e.printStackTrace();
	}
	return keypairs;
      } catch (IOException e2) {
	if (log.isDebugEnabled()) {
	  log.debug("Error extracting certificates from PFX.");
	  e2.printStackTrace();
	}
	return keypairs;
      }

      if (log.isDebugEnabled()) {
	log.debug("Extracting private keys");
      }
      try {
	keys = pfx.getAllPrivateKeys(null, rcvrPrivKey, rcvrCert);
	if ((keys == null) || (keys.length == 0)) {
	  if (log.isDebugEnabled()) {
	    log.debug("Got no private keys");
	  }
	  return keypairs;
	} else {
	  if (log.isDebugEnabled()) {
	    log.debug("Got " + keys.length + " private keys");
	  }
	}
      } catch (PKCSException e) {
	if (log.isDebugEnabled()) {
	  log.debug("Error extracting private keys from PFX.");
	  log.debug("Original Exception:");
	  e.getRelatedException().printStackTrace();
	  log.debug("PKCSException:");
	  e.printStackTrace();
	}
	return keypairs;
      } catch (IOException e2) {
	if (log.isDebugEnabled()) {
	  log.debug("Error extracting private keys from PFX.");
	  e2.printStackTrace();
	}
	return keypairs;
      }

      /*
	if (keys.length != certs.length) {
	if (log.isDebugEnabled()) {
	log.debug("Error: Number of certs does not match number of private keys");
	}
	return keypairs;
	}
      */

      keypairs = new PrivateKeyCert[keys.length];
      for (int i = 0 ; i < keys.length ; i++) {
	/* Check the trust of each certificate.
	 */
	if (log.isDebugEnabled()) {
	  log.debug("Checking certificate trust");
	}
	X509Certificate[] certChain = null;
	if (keyRing == null) {
	  if (log.isDebugEnabled()) {
	    log.debug("Warning: certificate trust cannot be verified");
	  }
	}
	else {
	  try {
	    certChain =keyRing.checkCertificateTrust((X509Certificate)certs[i]);
	  }
	  catch (Exception e) {
	    if (log.isDebugEnabled()) {
	      log.debug("Warning: Certificate is not trusted");
	    }
	    keypairs[i] = null;
	    continue;
	  }
	}
	CertificateStatus cs =
	  new CertificateStatus((X509Certificate)certs[i],
				CertificateOrigin.CERT_ORI_PKCS12,
				CertificateRevocationStatus.VALID,
				CertificateType.CERT_TYPE_END_ENTITY,
				CertificateTrust.CERT_TRUST_CA_SIGNED,
				null);
	if (log.isDebugEnabled()) {
	  log.debug("Private key in PKCS#12 envelope is trusted");
	}
	keypairs[i] = new PrivateKeyCert(keys[i], cs);
      }
      return keypairs;
    }
}
