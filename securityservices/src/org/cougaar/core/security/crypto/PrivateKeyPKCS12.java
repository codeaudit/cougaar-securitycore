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

import java.io.*;
import java.util.*;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import com.ibm.security.pkcs12.PKCS12PFX;
import com.ibm.security.pkcs8.PrivateKeyInfo;
import com.ibm.security.pkcsutil.PKCSException;

// Cougaar security services
import org.cougaar.core.security.util.CryptoDebug;
import org.cougaar.core.security.services.util.SecurityPropertiesService;

public class PrivateKeyPKCS12
{
  private DirectoryKeyStore directory = null;

  public PrivateKeyPKCS12(DirectoryKeyStore aDirectory)
  {
    directory = aDirectory;
  }

  
  /** @param privKey        The private key to store in a PKCS#12 enveloppe
   *  @param cert           The certificate to store in a PKCS#12 enveloppe
   *  @param signerPrivKey  The private key of the signer
   *  @param signerCert     The certificate of the signer
   *  @param rcvrCert       The certificate of the intended receiver
   */
  public byte[] protectPrivateKey(PrivateKey privKey,
				  Certificate cert,
				  PrivateKey signerPrivKey,
				  Certificate signerCert,
				  Certificate rcvrCert)
  {
    /* 
     * Create an array of certificates.  The certificates in the array 
     * belong to each intended receiver of the private information. 
     */
    if (CryptoDebug.debug) {
      System.out.println("Creating array of receiver certificates");
    }
    Certificate[] rcvrCerts = new Certificate[1];
    rcvrCerts[0] = rcvrCert;

    /* 
     * Create an empty PKCS12PFX to which the data items will be added.
     */
    if (CryptoDebug.debug) {
      System.out.println("Creating an empty PKCS12PFX");
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
      if (CryptoDebug.debug) {
	System.out.println("Adding certificate to the PFX");
      }
      pfx.addBagWithPubkeyPrivacy(cert, null, rcvrCerts);

      if (CryptoDebug.debug) {
	System.out.println("Adding signer certificate to the PFX");
      }
      pfx.addBagWithPubkeyPrivacy(signerCert, null, rcvrCerts);

      if (CryptoDebug.debug) {
	System.out.println("Adding private key to the PFX");
      }
      try {
	com.ibm.security.x509.AlgorithmId algid =
	  com.ibm.security.x509.AlgorithmId.get(privKey.getAlgorithm());
	PrivateKeyInfo pkinfo = new PrivateKeyInfo(algid, privKey.getEncoded(), null);
	pfx.addBagWithPubkeyPrivacy(pkinfo, null, rcvrCerts);
      } catch (java.security.NoSuchAlgorithmException ex) {
	if (CryptoDebug.debug) {
	  System.out.println("Error: " + ex);
	}
	return null;
      }
    } catch (PKCSException e) {
      if (CryptoDebug.debug) {
	System.out.println("Error adding data to the PFX.");
	System.out.println("Original Exception:");
	e.getRelatedException().printStackTrace();
      }
      return null;
    } catch (IOException e2) {
      System.out.println("Error adding data to the PFX.");
      e2.printStackTrace();
      return null;
    }

    /* Add the certificate of the signer, so that the receiver can
     * verify the signature.
     */
    try {
      if (CryptoDebug.debug) {
	System.out.println("Adding clear-text signer certificate to the PFX");
      }
      pfx.addBag(signerCert, null);
    } catch (PKCSException e) {
      if (CryptoDebug.debug) {
	System.out.println("Error adding signer certificate to the PFX.");
	System.out.println("Original Exception:");
	e.getRelatedException().printStackTrace();
      }
      return null;
    } catch (IOException e2) {
      if (CryptoDebug.debug) {
	System.out.println("Error adding signer certificate to the PFX.");
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
    if (CryptoDebug.debug) {
      System.out.println("Applying a digital signature to the PFX");
    }
    try {
      pfx.applySignature("SHA1", "RSA", signerCert, signerPrivKey);
    } catch (PKCSException e) {
      if (CryptoDebug.debug) {
	System.out.println("Error protecting PFX.");
	System.out.println("Original Exception:");
	e.getRelatedException().printStackTrace();
	System.out.println("PKCSException:");
	e.printStackTrace();
      }
      return null;
    } catch (IOException e2) {
      if (CryptoDebug.debug) {
	System.out.println("Error protecting PFX.");
	e2.printStackTrace();
      }
      return null;
    } catch (NoSuchAlgorithmException e3) {
      if (CryptoDebug.debug) {
	System.out.println("An HMAC algorithm is not supported");
	e3.printStackTrace();
      }
      return null;
    }
    
    ByteArrayOutputStream ba = new ByteArrayOutputStream();
    try {
      pfx.encode(ba);
    } catch (IOException e2) {
      if (CryptoDebug.debug) {
	System.out.println("Unable to encode PFX.");
	e2.printStackTrace();
      }
      return null;
    }
   
    return ba.toByteArray();
  }

  /** Extract information from a PKCS#12 PFX
   * @param pfxBytes       The DER encoded PFX
   * @param rcvrPrivKey    The private key of the receiver
   * @param rcvrCert       The certificate of the receiver
   */
  public PrivateKeyCert[] getPfx(byte[] pfxBytes,
				 PrivateKey rcvrPrivKey,
				 Certificate rcvrCert)
  {
    PKCS12PFX pfx = new PKCS12PFX();
    Certificate[] certs = null;
    PrivateKey[] keys = null;
    PrivateKeyCert[] keypairs = null;

    /* 
     * Construct a PFX from its DER-encoding. In this PFX, public
     * key mode was used to protect data privacy and ensure data integrity. 
     */
    try {
      if (CryptoDebug.debug) {
	System.out.println("Creating PKCS12 envelope from DER encoded value");
      }
      pfx = new PKCS12PFX(pfxBytes);
    } catch (IOException e) {
      if (CryptoDebug.debug) {
	System.out.println("Cannot create PFX from DER-encoding."); 
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
      if (CryptoDebug.debug) {
	System.out.println("Error retrieving signer certificate from PFX.");
	System.out.println("Original Exception:");
	e.getRelatedException().printStackTrace();
	System.out.println("PKCSException:");
	e.printStackTrace();
	return keypairs;
      }
    } catch (IOException e2) {
      if (CryptoDebug.debug) {
	System.out.println("Error retrieving signer certificate from PFX.");
	e2.printStackTrace();
	return keypairs;
      }
    }
    if(CryptoDebug.debug) {
      System.out.println("The PKCS12 envelope contains "
			 + ((signerCerts != null) ? signerCerts.length : 0)
			 + " unprotected certificates");
    }
    if (signerCerts == null || signerCerts.length != 1) {
      if (CryptoDebug.debug) {
	System.out.println("Unable to retrieve signer certificate");
      }
      return keypairs;
    }
    Certificate signerCert = signerCerts[0];

    /* Check the trust of the signer certificate.
     */
    if (CryptoDebug.debug) {
      System.out.println("Checking signer certificate trust for "
			 + signerCert.toString());
    }
    X509Certificate[] signerCertChain = null;
    try {
      signerCertChain =
	directory.checkCertificateTrust((X509Certificate)signerCert);
    }
    catch (Exception e) {
      if (CryptoDebug.debug) {
	System.out.println("Warning: Signer Certificate is not trusted" + e);
      }
      return keypairs;
    }

    /*
     * Verify the digital signature to be sure that the data has not been 
     * tampered with.  You must use the public key corresponding to the 
     * private key that signed the PFX.  This public key is usually found
     * within a certificate.
     */
    if (CryptoDebug.debug) {
      System.out.println("Verifying the PFX digital signature");
    }
    try {
      if (pfx.verifySignature(signerCert)) {
	if (CryptoDebug.debug) {
	  System.out.println("The PFX data is verified");
	}
      } else {
	if (CryptoDebug.debug) {
	  System.out.println("The PFX data is not verified");
	}
	return keypairs;
      }
    } catch (PKCSException e) {
      if (CryptoDebug.debug) {
	System.out.println("Error verifying signature.");
	System.out.println("Original Exception:");
	e.getRelatedException().printStackTrace();
	System.out.println("PKCSException:");
	e.printStackTrace();
      }
      return keypairs;
    } catch (NoSuchAlgorithmException e2) {
      if (CryptoDebug.debug) {
	System.out.println("Unsupported signature algorithm.");
	e2.printStackTrace();
      }
      return keypairs;
    } catch (IOException e3) {
      if (CryptoDebug.debug) {
	System.out.println("IOException verifying signature.");
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
    if (CryptoDebug.debug) {
      System.out.println("Extracting certificates");
    }
    try {
      certs = pfx.getAllCertificates(null, rcvrPrivKey, rcvrCert);
      if ((certs == null) || (certs.length == 0)) {
	if (CryptoDebug.debug) {
	  System.out.println("Got no certificates");
	}
	return keypairs;
      } else {
	if (CryptoDebug.debug) {
	  System.out.println("Got " + certs.length + " certificates");
	  for (int i = 0 ; i < certs.length ; i++) {
	    System.out.println("Certificate[" + i + "]="
			       + certs[i]);
	  }
	}
      }
    } catch (PKCSException e) {
      if (CryptoDebug.debug) {
	System.out.println("Error extracting certificates from PFX.");
	System.out.println("Original Exception:");
	e.getRelatedException().printStackTrace();
	System.out.println("PKCSException:");
	e.printStackTrace();
      }
      return keypairs;
    } catch (IOException e2) {
      if (CryptoDebug.debug) {
	System.out.println("Error extracting certificates from PFX.");
	e2.printStackTrace();
      }
      return keypairs;
    }

    if (CryptoDebug.debug) {
      System.out.println("Extracting private keys");
    }
    try {
      keys = pfx.getAllPrivateKeys(null, rcvrPrivKey, rcvrCert);
      if ((keys == null) || (keys.length == 0)) {
	if (CryptoDebug.debug) {
	  System.out.println("Got no private keys");
	}
	return keypairs;
      } else {
	if (CryptoDebug.debug) {
	  System.out.println("Got " + keys.length + " private keys");
	}
      }
    } catch (PKCSException e) {
      if (CryptoDebug.debug) {
	System.out.println("Error extracting private keys from PFX.");
	System.out.println("Original Exception:");
	e.getRelatedException().printStackTrace();
	System.out.println("PKCSException:");
	e.printStackTrace();
      }
      return keypairs;
    } catch (IOException e2) {
      if (CryptoDebug.debug) {
	System.out.println("Error extracting private keys from PFX.");
	e2.printStackTrace();
      }
      return keypairs;
    }

    /*
    if (keys.length != certs.length) {
      if (CryptoDebug.debug) {
	System.out.println("Error: Number of certs does not match number of private keys");
      }
      return keypairs;
    }
    */

    keypairs = new PrivateKeyCert[keys.length];
    for (int i = 0 ; i < keys.length ; i++) {
      /* Check the trust of each certificate.
       */
      if (CryptoDebug.debug) {
	System.out.println("Checking certificate trust");
      }
      X509Certificate[] certChain = null;
      if (directory == null) {
	if (CryptoDebug.debug) {
	  System.out.println("Warning: certificate trust cannot be verified");
	}
      }
      else {
	try {
	  certChain =
	    directory.checkCertificateTrust((X509Certificate)certs[i]);
	}
	catch (Exception e) {
	  if (CryptoDebug.debug) {
	    System.out.println("Warning: Certificate is not trusted");
	  }
	  keypairs[i] = null;
	  continue;
	}
      }
      CertificateStatus cs =
	new CertificateStatus((X509Certificate)certs[i], true,
			      CertificateOrigin.CERT_ORI_PKCS12,
			      CertificateType.CERT_TYPE_END_ENTITY,
			      CertificateTrust.CERT_TRUST_CA_SIGNED,
			      null);
      if (CryptoDebug.debug) {
        System.out.println("Private key in PKCS#12 envelope is trusted");
      }
      keypairs[i] = new PrivateKeyCert(keys[i], cs);
    }
    return keypairs;
  }
}
