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

package com.nai.security.bootstrap;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.jar.*;
import java.util.zip.*;
import sun.misc.BASE64Encoder;

import com.nai.security.util.SecurityPropertiesService;
import org.cougaar.core.security.crypto.CryptoServiceProvider;

public class CertificateVerifier { 

  private SecurityPropertiesService secprop = null;

  /* max number of certificates in a certificate chain */
  protected static final int MAX_CERTS = 100;

  /* used in keyUsage field of the certificate to indicate whether
       class loading capabilities are granted */
  protected static final int PACKAGE_SIGNING_CAPABILITY_BIT = 9;

  /* default, will be overriden if org.cougaar.core.security.bootstrap.verifyKeyUsage is set */
  protected static boolean verifyJarSigningCapability = false;

  // protected String defaultKeyStorePath = "/home/afiglin/.keystore";
  protected String defaultKeyStorePath = null;
  protected String keyStorePath = null;
  
  protected X509Certificate certificates[] = null;


  public CertificateVerifier() {
    // TODO. Modify following line to use service broker instead
    secprop = CryptoServiceProvider.getSecurityProperties();

    keyStorePath = secprop.getProperty(secprop.BOOTSTRAP_KEYSTORE, null);

    String p = secprop.getProperty(secprop.BOOTSTRAP_VERIFYKEY);
    if (p != null  && p.equals("true")) {
        verifyJarSigningCapability = true;
    }
    else if (p != null  && p.equals("false")) {
        verifyJarSigningCapability = false;
    }

    certificates = new X509Certificate[MAX_CERTS];
  }

  /** check if class loading capabilities are granted */
  protected boolean hasJarSigningCapability(X509Certificate c) {
    if (verifyJarSigningCapability) {
      boolean[] usages = c.getKeyUsage();
      if (usages != null && usages[PACKAGE_SIGNING_CAPABILITY_BIT]) {
	return true;
      }
      else
	return false;
    }
    else return true;
  }
  
  /** helper method to check if the signature version inside .SF file is valid */
  protected boolean validSigVersion(JarFile jf, JarEntry je) throws IOException {
    InputStream in = jf.getInputStream(je);
    InputStreamReader inReader = new InputStreamReader(in);
    BufferedReader buffReader = new BufferedReader(inReader);
    String line = buffReader.readLine();
    if (line.equals("Signature-Version: 1.0")) {
        return true;
    }
    return false;
  }


  /** This method will verify whether the signature version line is in place in each .SF file
      and will throw SignatureException if it's missing or if it contains the wrong signature version.
      This verification step is important because 
      sun.security.util.SignatureFileVerifier.process(Hashtable hash) that is transparently invoked here
      will return if this line does not exist or contains wrong version number.  It will then not try to
      verify the digest value that appears in the header against the digest value of the manifest file.  
  */
  protected void verifySigVersion(JarFile jf, Vector sigFiles) throws IOException, SignatureException {
    for (int i=0; i<sigFiles.size(); i++) {
      if (!validSigVersion(jf, (JarEntry)sigFiles.elementAt(i))) {
        throw new SignatureException("Problem with " + jf.getName() + "/" + 
        ((JarEntry)sigFiles.elementAt(i)).getName() + ". \n\tInvalid or missing signature version.");
      }
    }
  }


  /** verifies that a certificate from the signed jar file matches
      some trusted certificate in a key store
  */
  protected void verify(JarFile jf) throws IOException, FileNotFoundException,
            CertificateException, CertificateVerificationException, SignatureException, 
            KeyStoreException, NoSuchAlgorithmException, NoManifestFoundException {   
    boolean certsExist = false;
    Manifest manifest = null;
    manifest = jf.getManifest();
    if (manifest == null) {
      throw new NoManifestFoundException(jf.getName());
    }
    
    verifySigVersion(jf, getJarEntries(jf, ".SF"));

    Vector dsaEntries = getJarEntries(jf, ".DSA");
    for (int i = 0; i < dsaEntries.size(); i++) {
      if ((certificates = retrieveCertificateChain(jf, (JarEntry)dsaEntries.elementAt(i))) != null) {
        certsExist = (certificates != null && certificates.length > 0);
        if (certsExist) {
          for (int j = 0; j < certificates.length; j++) {
            if (certificates[j] != null && inKeyStore(certificates[j]) && 
                        hasJarSigningCapability(certificates[j]))
              return;
          }
        }
      }
    }
    throw new CertificateVerificationException(jf.getName());    

  }
  
  /** check if given certificate is trusted */
  protected boolean inKeyStore(X509Certificate cert) 
    throws CertificateException, IOException, FileNotFoundException,
	   KeyStoreException, NoSuchAlgorithmException{
    KeyStore ks = KeyStore.getInstance("JKS");
    InputStream in;
    if (keyStorePath != null)
        in = new FileInputStream(keyStorePath);
    else
      in = new FileInputStream(defaultKeyStorePath);

    if (in != null) {
      ks.load(in, null);
      Enumeration aliases = ks.aliases();
      while(aliases.hasMoreElements()) {
        X509Certificate c = (X509Certificate)(ks.getCertificate((String)aliases.nextElement()));
        if (c.equals(cert)) {
            return true;
        }
      }     
    }

    return false; //keystore not available or no certificate with jar signing capability found
  }


  /** Get a chain of X.509 certificates from .DSA file in the META-INF directory.
   *  .DSA file is generated when jar file is signed using jarsigner tool */
  private X509Certificate[] retrieveCertificateChain(DataInputStream dis) throws CertificateException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    Collection c = cf.generateCertificates(dis);
    if (c != null) {
      Iterator i = c.iterator();
      int counter = 0;
      while (i.hasNext()) {
        certificates[counter] = (X509Certificate)i.next();
	counter ++;
      }
    }
    return certificates;
  }
  
  /** Get a chain of X.509 certificates from .DSA file in the META-INF 
   *  directory of the given jar file.
   * .DSA file is generated when jar file is signed using jarsigner tool */
  protected X509Certificate[] retrieveCertificateChain(JarFile jf, JarEntry dsa)
    throws FileNotFoundException, IOException, CertificateException {
    if (dsa != null && jf != null) {
       InputStream in = jf.getInputStream(dsa);
       DataInputStream dis = new DataInputStream(in);
       int len = Integer.parseInt(String.valueOf(dsa.getSize()));

       return (retrieveCertificateChain(dis));
    }
    return null;
  }
    

  /** Get JarEntries for META-INF/*.DSA or *.SF files (could be used for any other type of entries as well)
   *  Type indicates whether we're interested in .DSA or .SF entries ... */
  protected  Vector getJarEntries(JarFile jf, String type) throws FileNotFoundException, IOException {
    Vector dsaFiles = new Vector(); 
    Enumeration e = jf.entries();
    JarEntry thisEntry = null;
    while(e.hasMoreElements()) {
      thisEntry = (JarEntry)e.nextElement();
      if ( thisEntry.getName().toUpperCase().startsWith("META-INF") &&
	   thisEntry.getName().toUpperCase().endsWith(type) ) {   
        dsaFiles.addElement(thisEntry);
      }
    }
    
    return dsaFiles;  // file does not exist --> jar file has not been signed
  }
  
}
