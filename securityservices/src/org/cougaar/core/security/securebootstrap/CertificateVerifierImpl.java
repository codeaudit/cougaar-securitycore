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


package org.cougaar.core.security.securebootstrap;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/*
 * A Jar file signature verifier.
 * There can be only one instance of the verifier, ie even if the
 * class is loaded in different class loaders, there will only one
 * instance. Jar file signatures need not be checked twice from
 * two different class loaders.
 */
public class CertificateVerifierImpl
  extends BaseSingleton
  implements CertificateVerifier
{
  /* max number of certificates in a certificate chain */
  protected static final int MAX_CERTS = 100;

  /* used in keyUsage field of the certificate to indicate whether
     class loading capabilities are granted */
  protected static final int PACKAGE_SIGNING_CAPABILITY_BIT = 9;

  /** default, will be overriden if
   * org.cougaar.core.security.bootstrap.verifyKeyUsage is set */
  protected static boolean verifyJarSigningCapability = false;

  // protected String defaultKeyStorePath = "/home/afiglin/.keystore";
  protected String defaultKeyStorePath = null;
  protected String keyStorePath = null;
  
  protected X509Certificate certificates[] = null;

  /** Maintains a hashtable of jar files and their trust status
   */
  private Hashtable _jarFiles = new Hashtable();

  /*
   * This is an instance of this class, or it may be instead a
   * java.lang.reflect.Proxy wrapping an instance from the original
   * classloader.
   */
  private static CertificateVerifier _certificateVerifier;

  /** Log file to store Jar verification errors */
  private static SecurityLog _securelog;

  /** The time when the verifier was first invoked. */
  private static Date _startupTime;

  static {
    _startupTime = new Date();
  }

  protected CertificateVerifierImpl() {
    keyStorePath =
      System.getProperty("org.cougaar.core.security.bootstrap.keystore", null);

    String p =
      System.getProperty("org.cougaar.core.security.bootstrap.verifyKeyUsage");
    if (p != null  && p.equals("true")) {
      verifyJarSigningCapability = true;
    }
    else if (p != null  && p.equals("false")) {
      verifyJarSigningCapability = false;
    }
    certificates = new X509Certificate[MAX_CERTS];
    _securelog = SecurityLogImpl.getInstance();
  }

  public static synchronized CertificateVerifier getInstance() {
    _certificateVerifier = (CertificateVerifier)
      getInstance(CertificateVerifierImpl.class,
		  CertificateVerifier.class,
		  _certificateVerifier);
    return _certificateVerifier;
  }

  /** check if class loading capabilities are granted */
  private boolean hasJarSigningCapability(X509Certificate c) {
    if (verifyJarSigningCapability) {
      boolean[] usages = c.getKeyUsage();
      if (usages != null && usages[PACKAGE_SIGNING_CAPABILITY_BIT]) {
	return true;
      }
      else {
	return false;
      }
    }
    else return true;
  }
  
  /** helper method to check if the signature version inside .SF file
   * is valid */
  private boolean validSigVersion(JarFile jf, JarEntry je)
    throws IOException {
    InputStream in = jf.getInputStream(je);
    InputStreamReader inReader = new InputStreamReader(in);
    BufferedReader buffReader = new BufferedReader(inReader);
    String line = buffReader.readLine();
    if (line.equals("Signature-Version: 1.0")) {
      return true;
    }
    return false;
  }

  /**
   * This method will verify whether the signature version line is in place
   * in each .SF file and will throw SignatureException if it's missing or
   * if it contains the wrong signature version.
   * This verification step is important because
   * sun.security.util.SignatureFileVerifier.process(Hashtable hash) that is
   * transparently invoked here will return if this line does not exist or
   * contains wrong version number.  It will then not try to
   * verify the digest value that appears in the header against the digest
   * value of the manifest file.  
   */
  private void verifySigVersion(JarFile jf, Vector sigFiles)
    throws IOException, SignatureException {
    for (int i=0; i<sigFiles.size(); i++) {
      if (!validSigVersion(jf, (JarEntry)sigFiles.elementAt(i))) {
	SignatureException e =
	  new SignatureException("Problem with " + jf.getName() + "/" + 
				 ((JarEntry)sigFiles.elementAt(i)).getName()
				 + ". \n\tInvalid or missing signature version.");
        throw e;
      }
    }
  }

  /** verifies that a certificate from the signed jar file matches
      some trusted certificate in a key store
  */
  public void verify(JarFile jf)
    throws CertificateVerificationException {
    URL jfURL = null;
    try {
      jfURL = new URL(jf.getName());
    }
    catch (Exception e) {
      // Nothing to do. This is used for information purposes only.
    }
    JarFileStatus status = (JarFileStatus) _jarFiles.get(jf.getName());
    if (status != null) {
      if (status._isTrusted) {
	return;
      }
      else {
	throw status._exception;
      }
    }
    boolean certsExist = false;
    Manifest manifest = null;
    try {
      manifest = jf.getManifest();
    }
    catch (IOException ex) {
      CertificateVerificationException e =
	new CertificateVerificationException
	(jf.getName(), ex);
      if (!isXmlConfigurationFile(jf)) {
        _securelog.logJarVerificationError(jfURL, e);
      }
      _jarFiles.put(jf.getName(), new JarFileStatus(false, e));
      throw e;
    }

    if (manifest == null) {
      CertificateVerificationException e =
	new CertificateVerificationException
	(jf.getName(), new NoManifestFoundException(jf.getName()));
      if (!isXmlConfigurationFile(jf)) {
        _securelog.logJarVerificationError(jfURL, e);
      }
      _jarFiles.put(jf.getName(), new JarFileStatus(false, e));
      throw e;
    }

    try {
      verifySigVersion(jf, getJarEntries(jf, ".SF"));
    }
    catch (Exception ex) {
      CertificateVerificationException e =
	new CertificateVerificationException
	(jf.getName(), ex);
      if (!isXmlConfigurationFile(jf)) {
        _securelog.logJarVerificationError(jfURL, e);
      }
      _jarFiles.put(jf.getName(), new JarFileStatus(false, e));
      throw e;
    }

    Vector dsaEntries = null;
    try {
      dsaEntries = getJarEntries(jf, ".DSA");
    }
    catch (Exception ex) {
      CertificateVerificationException e =
	new CertificateVerificationException
	(jf.getName(), ex);
      if (!isXmlConfigurationFile(jf)) {
        _securelog.logJarVerificationError(jfURL, e);
      }
      _jarFiles.put(jf.getName(), new JarFileStatus(false, e));
      throw e;
    }

    for (int i = 0; i < dsaEntries.size(); i++) {
      try {
	certificates = retrieveCertificateChain
	  (jf, (JarEntry)dsaEntries.elementAt(i));
      }
      catch (Exception ex) {
	CertificateVerificationException e =
	  new CertificateVerificationException
	  (jf.getName(), ex);
        if (!isXmlConfigurationFile(jf)) {
          _securelog.logJarVerificationError(jfURL, e);
        }
	_jarFiles.put(jf.getName(), new JarFileStatus(false, e));
	throw e;
      }

      if (certificates != null) {
        certsExist = (certificates != null && certificates.length > 0);
        if (certsExist) {
          for (int j = 0; j < certificates.length; j++) {
            if (certificates[j] != null) {
	      boolean inStore = false;
	      try {
		inStore = inKeyStore(certificates[j]);
	      }
	      catch (Exception ex) {
		CertificateVerificationException e =
		  new CertificateVerificationException
		  (jf.getName(), ex);
                if (!isXmlConfigurationFile(jf)) {
		  _securelog.logJarVerificationError(jfURL, e);
                }
		_jarFiles.put(jf.getName(), new JarFileStatus(false, e));
		throw e;
	      }

	      if (inStore && hasJarSigningCapability(certificates[j])) {
		boolean istrusted=false;
		try {
		  istrusted=isTrusted((X509Certificate)certificates[j]);
		}
		catch (CertificateExpiredException cee) {
		  CertificateVerificationException e =
		    new CertificateVerificationException
		    (jf.getName(), cee);
                  if (!isXmlConfigurationFile(jf)) {
		    _securelog.logJarVerificationError(jfURL, e);
                  }
		  _jarFiles.put(jf.getName(), new JarFileStatus(false, e));
		  throw e;
		}
		catch (CertificateNotYetValidException cye) {
		  CertificateVerificationException e =
		    new CertificateVerificationException
		    (jf.getName(), cye);
                  if (!isXmlConfigurationFile(jf)) {
		    _securelog.logJarVerificationError(jfURL, e);
                  }
		  _jarFiles.put(jf.getName(), new JarFileStatus(false, e));
		  throw e;
		}
		if(istrusted) {
		  _jarFiles.put(jf.getName(), new JarFileStatus(true, null));
		  return;
		}
	      }
	    }
          }
        }
      }
    }
    CertificateVerificationException e =
      new CertificateVerificationException
      (jf.getName(), new Exception("Jar file does not have any certificate"));
    if (!isXmlConfigurationFile(jf)) {
      _securelog.logJarVerificationError(jfURL, e);
    }
    _jarFiles.put(jf.getName(), new JarFileStatus(false, e));
    throw e;
  }
  
  /*
   * Verifies whether current certificate is trusted or not. As all the
   * certificates in the bootstrap keystore are self signed the only way to
   * check trust is their validity.
  */
  private boolean isTrusted(X509Certificate certificate)
    throws CertificateExpiredException,
    CertificateNotYetValidException {
    boolean istrusted =false;
    certificate.checkValidity();
    istrusted=true;
    return istrusted;
  }  
  
  /** check if given certificate is trusted */
  private boolean inKeyStore(X509Certificate cert) 
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
        X509Certificate c =
	  (X509Certificate)(ks.getCertificate((String)aliases.nextElement()));
        if (c.equals(cert)) {
	  return true;
        }
      }     
    }
    // keystore not available or no certificate with jar signing
    // capability found
    return false;
  }


  /** Get a chain of X.509 certificates from .DSA file in the META-INF
   * directory.
   * .DSA file is generated when jar file is signed using jarsigner tool */
  private X509Certificate[] retrieveCertificateChain(DataInputStream dis)
    throws CertificateException {
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
  
  /** Get a chain of X509 certificates from a DSA file in the META-INF 
   *  directory of the given jar file.
   *  The DSA file is generated when jar file is signed using jarsigner tool
   */
  private X509Certificate[] retrieveCertificateChain(JarFile jf, JarEntry dsa)
    throws FileNotFoundException, IOException, CertificateException {
    if (dsa != null && jf != null) {
      InputStream in = jf.getInputStream(dsa);
      DataInputStream dis = new DataInputStream(in);
      int len = Integer.parseInt(String.valueOf(dsa.getSize()));
      X509Certificate[] certs = retrieveCertificateChain(dis);
      dis.close();
      in.close();
      return certs;
    }
    return null;
  }
    

  /** Get JarEntries for META-INF/*.DSA or *.SF files (could be used for
   * any other type of entries as well)
   * Type indicates whether we're interested in .DSA or .SF entries ... */
  private  Vector getJarEntries(JarFile jf, String type)
    throws FileNotFoundException, IOException {
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

  private class JarFileStatus {
    public JarFileStatus(boolean isTrusted,
			 CertificateVerificationException e) {
      _isTrusted = isTrusted;
      _exception = e;
    }

    /** true if the Jar file signature is OK. False otherwise.
     */
    public boolean _isTrusted;

    /** If the Jar file was not signed properly, the exception
     *  that was raised during the first check
     */
    public CertificateVerificationException _exception;
  }

  /**
   * Checks whether the Jar file is a configuration file.
   * ACME builds and generates jar files containing XML configuration files on the fly.
   * Before a node is started, ACME generates the XML configuration file, jars it
   * and signs the jar file. Then ACME starts the node. These operations happens in parallel.
   * This means one node may start and verify all the jar files while ACME is in the middle of
   * building a configuration jar file for another node. This results in annoying IDMEF messages.
   * So we do not report IDMEF messages for files that have the ".xml.jar" suffix, because we
   * don't care about them.
   * We do not report the problem as IDMEF, AND we reject the jar file as invalid.
   */
  private boolean isXmlConfigurationFile(JarFile jf) {
    return ( ((new Date()).getTime() - _startupTime.getTime()) < (60 * 1000)  &&
         jf.getName().endsWith(".xml.jar")); 
  }
}
