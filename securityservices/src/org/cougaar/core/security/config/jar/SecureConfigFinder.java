/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc
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

package org.cougaar.core.security.config.jar;

import java.security.GeneralSecurityException;
import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.net.URL;
import java.net.JarURLConnection;
import java.util.Map;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.regex.PatternSyntaxException;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.Logging;

// Cougaar core infrastructure
import org.cougaar.util.jar.JarConfigFinder;

// Cougaar security services
import org.cougaar.core.security.securebootstrap.CertificateVerifier;
import org.cougaar.core.security.securebootstrap.CertificateVerifierImpl;
import org.cougaar.core.security.securebootstrap.SecurityLog;
import org.cougaar.core.security.securebootstrap.SecurityLogImpl;

/**
 * A secure config finder that looks configuration files in signed jar files
 */
public class SecureConfigFinder
  extends JarConfigFinder
{
  private static final Logger _logger =
  Logging.getLogger(SecureConfigFinder.class);

  /** Log file to store Jar verification errors */
  private static SecurityLog _securelog;

  /** A utility to check the signatures of JAR files.
   */
  private CertificateVerifier _certificateVerifier;

  private static final String EXCEPTION_LIST_FILE_NAME = "secureConfig.conf";

  /** A list of regular expressions. If a URL matches one of the
   * regular expression, the configuration file with that URL
   * can be loaded.
   */
  private List _exceptionListRegularExpressions;

  public SecureConfigFinder() {
    super();
    initialize();
  }
  public SecureConfigFinder(String path) {
    super(path);
    initialize();
  }
  public SecureConfigFinder(String path, Map props) {
    super(path, props);
    initialize();
  }
  public SecureConfigFinder(String module, String path) {
    super(module, path);
    initialize();
  }
  public SecureConfigFinder(String module, String path, Map props) {
    super(module, path, props);
    initialize();
  }

  private void initialize() {
    _certificateVerifier = CertificateVerifierImpl.getInstance();
    _securelog = SecurityLogImpl.getInstance();
    _exceptionListRegularExpressions = new ArrayList();
  }
  
  private void readExceptionList() {
    InputStream is = null;
    try {
      is = open(EXCEPTION_LIST_FILE_NAME);
    }
    catch (IOException e) {
      if (_logger.isInfoEnabled()) {
	_logger.info("No regular expression file was found (exception list)");
      }
      return;
    }
    if (is == null) {
      return;
    }
    BufferedReader br = new BufferedReader(new InputStreamReader(is));
    String line = null;
    try {
      while ((line = br.readLine()) != null) {
	if (line.startsWith("#")) {
	  continue;
	}
	try {
	  Pattern p = Pattern.compile(line);
	  _exceptionListRegularExpressions.add(p);
	}
	catch (PatternSyntaxException e) {
	  if (_logger.isWarnEnabled()) {
	    _logger.warn("Unable to parse regular expression: " + line);
	  }
	}
      }
    }
    catch (IOException e) {
      if (_logger.isWarnEnabled()) {
	_logger.warn("Unable to read regular expression file");
      }
    }
  }

  /**
   * Check the integrity of a jar file. Do nothing in the base
   * implementation.
   */
  protected void verifyJarFile(JarFile aJarFile)
    throws GeneralSecurityException {
    if (!acceptUnsignedJarFiles()) {
      //do certificate verification, throw an exception
      //and exclude from urls if not trusted
      _certificateVerifier.verify(aJarFile);
    }
  }

  /**
   * Determines whether a simple configuration file may be loaded
   * without being signed.
   * This method tries to match the provided URL against a list
   * of regular expressions. This allows specific configuration files
   * to be loaded even if they are not signed.
   *
   * @param aURL The URL of a simple (unsigned) configuration file.
   */
  protected boolean isValidUrl(URL aURL) {
    if (aURL == null) {
      return false;
    }
    String url = aURL.toString();
    Iterator it = _exceptionListRegularExpressions.iterator();
    while (it.hasNext()) {
      Pattern pattern = (Pattern) it.next();
      Matcher matcher = pattern.matcher(url);
      boolean result = matcher.find();
      if (result) {
	if (_logger.isDebugEnabled()) {
	  _logger.debug(url + " may be loaded without signature");
	}
	return true;
      }
    }
    if (_logger.isDebugEnabled()) {
      _logger.debug(url + " cannot be loaded without signature");
    }
    return false;
  }

  /**
   * Verify the integrity of the data contained at a URL.
   * Some integrity issues might be discovered late when reading
   * an input stream. For example, digest errors are discovered
   * when the entire stream has been read. This gives the opportunity
   * for a secure file finder to verify the data before the stream
   * is returned to the caller.
   *
   * Does nothing in the default implementation.
   * @param aURL the URL to check.
   * @exception IOException if an IO Exception occurs while opening the stream
   * @exception GeneralSecurityException if there was a problem while checking
   *                the integrity of the input stream.
   */
  protected void verifyInputStream(URL aURL)
    throws IOException, GeneralSecurityException {
    try {
      // We have to read the file for signature verification.
      InputStream is = new SecureJarFilterStream(aURL.openStream());
      is.close();
    }
    catch (GeneralSecurityException e) {
      logSecurityEvent(aURL, e);
      throw e;
    }
  }

  private boolean acceptUnsignedJarFiles() {
    return false;
  }

  /**
   * @deprecated
   */
  protected boolean acceptUnsignedFiles() {
    return false;
  }

  /** Do not allow unsigned files by default.
   */
  protected boolean jarFilesOnly() {
    return true;
  }

  protected File copyFileToTempDirectory(URL aUrl, String aFilename)
    throws IOException, GeneralSecurityException {
    File tempFile = null;
    try {
      tempFile = super.copyFileToTempDirectory(aUrl, aFilename);
    }
    catch (SecurityException sex) {
      _logger.warn("Unable to copy to temp directory: " + aFilename
		   + ". Reason: " + sex);
      
      JarURLConnection juc = (JarURLConnection)aUrl.openConnection();

      if (juc != null) {
	logSecurityEvent(juc.getURL(), sex);
      }
      else {
	// Log anyway. This may cause the system to log the same
	// event more than once.
	logSecurityEvent(null, sex);
      }

      // In addition, remove the file from the cache.
      // It cannot be accessed.
      _logger.debug("Removing " + aFilename + " from cache");
      _file2URLs.remove(aUrl);

      if (tempFile.exists()) {
	// Delete the file, as the components may try to open the
	// file anyway.
	tempFile.delete();
	tempFile = null;
      }
    }
    return tempFile;
  }

  private void logSecurityEvent(URL url, Exception ex) {
    _securelog.logJarVerificationError(url, ex);
  }

  /**
   * Determines if ConfigFinder client may specify absolute file names.
   */
  protected boolean acceptAbsoluteFileNames() {
    return true;
  }

}
