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


package org.cougaar.core.security.config.jar;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.JarURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.cougaar.core.security.securebootstrap.CertificateVerifier;
import org.cougaar.core.security.securebootstrap.CertificateVerifierImpl;
import org.cougaar.core.security.securebootstrap.SecurityLog;
import org.cougaar.core.security.securebootstrap.SecurityLogImpl;
import org.cougaar.core.security.util.ConcurrentHashMap;
import org.cougaar.util.jar.JarConfigFinder;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

/**
 * A secure config finder that looks configuration files in signed jar files
 */
public class SecureConfigFinder
  extends JarConfigFinder
{
  private static final Logger _logger =
  LoggerFactory.getInstance().createLogger(SecureConfigFinder.class);

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
  private boolean _jarFilesOnly = true;

  /**
   * A Map from URLs to temporary Files.
   */
  private static ConcurrentHashMap m_filesProcessed = new ConcurrentHashMap();


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
    if (_certificateVerifier == null) {
      String s = "Unable to get certificate verifier";
      if (_logger.isWarnEnabled()) {
	_logger.warn(s);
      }
      throw new RuntimeException(s);
    }
    _securelog = SecurityLogImpl.getInstance();
    _exceptionListRegularExpressions = new ArrayList();
    readExceptionList();
  }
  
  public InputStream open(String aURL)
    throws IOException {
    if (_logger.isInfoEnabled()) {
      _logger.info("Opening " + aURL);
    }
    return super.open(aURL);
    /*
    Turn the following code to identify components that do not
    release resources.
    InputStream is = super.open(aURL);
    return new DebugInputStream(is);
    */
  }

  private void readExceptionList() {
    if (_logger.isDebugEnabled()) {
      _logger.debug("Reading SecureConfigFinder configuration file");
    }
    InputStream is = null;
    try {
      is = open(EXCEPTION_LIST_FILE_NAME);
    }
    catch (IOException e) {
      if (_logger.isInfoEnabled()) {
	_logger.info("Unable to open SecureConfigFinder configuration file");
      }
      return;
    }
    if (is == null) {
      if (_logger.isInfoEnabled()) {
	_logger.info("SecureConfigFinder configuration file not found");
      }
      return;
    }
    BufferedReader br = new BufferedReader(new InputStreamReader(is));
    String line = null;
    Pattern p1 = Pattern.compile("(exceptionPattern=)(.*)");
    Pattern p2 = Pattern.compile("(jarFilesOnly=)(.*)");
    try {
      while ((line = br.readLine()) != null) {
	if (line.startsWith("#")) {
	  continue;
	}
	Matcher matcher = p1.matcher(line);
	if (matcher.find()) {
	  try {
	    Pattern p = Pattern.compile(matcher.group(2));
	    _exceptionListRegularExpressions.add(p);
	    if (_logger.isDebugEnabled()) {
	      _logger.debug("New exception pattern: " + p.pattern());
	    }
	  }
	  catch (PatternSyntaxException e) {
	    if (_logger.isWarnEnabled()) {
	      _logger.warn("Unable to parse regular expression: " + line);
	    }
	  }
	  continue;
	}
	matcher = p2.matcher(line);
	if (matcher.find()) {
	  _jarFilesOnly = (Boolean.valueOf(matcher.group(2))).booleanValue();
	    if (_logger.isDebugEnabled()) {
	      _logger.debug("jarFilesOnly:" + _jarFilesOnly);
	    }
	}
      }
    }
    catch (IOException e) {
      if (_logger.isWarnEnabled()) {
	_logger.warn("Unable to read regular expression file");
      }
    }
    try {
      br.close();
    }
    catch (IOException e) {}
  }

  /**
   * Check the integrity of a jar file. Do nothing in the base
   * implementation.
   */
  protected void verifyJarFile(JarFile aJarFile)
    throws GeneralSecurityException {
    if (_logger.isInfoEnabled()) {
      _logger.info("Verify JarFile " + aJarFile.getName());
    }
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
    if (_logger.isDebugEnabled()) {
      _logger.debug("Check validity of " + url);
    }
    Iterator it = _exceptionListRegularExpressions.iterator();
    while (it.hasNext()) {
      Pattern pattern = (Pattern) it.next();
      Matcher matcher = pattern.matcher(url);
      boolean result = matcher.find();
      if (_logger.isDebugEnabled()) {
	_logger.debug("Trying against " + pattern.pattern() + " - Result: " + result);
      }
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
    boolean verified = false;
    if (m_verifiedUrls.contains(aURL)) {
       verified = true;
    }
    if (_logger.isInfoEnabled()) {
      _logger.info("Verify InputStream. Verified=" + verified  + " " + aURL);
    }
    if (verified) {
      return;
    }
    try {
      // We have to read the file for signature verification.
      InputStream is = new SecureJarFilterStream(aURL);
      is.close();
      m_verifiedUrls.add(aURL);
    }
    catch (GeneralSecurityException e) {
      logSecurityEvent(aURL, e);
      throw e;
    }
  }

  /** A Set containing all the URLs that have been verified.
   */
  private Set m_verifiedUrls = new HashSet();

  private boolean acceptUnsignedJarFiles() {
    return false;
  }

  /** Do not allow unsigned files by default.
   */
  protected boolean jarFilesOnly() {
    return _jarFilesOnly;
  }

  private File superCopyFileToTempDirectory(URL aUrl, String aFilename)
    throws IOException, GeneralSecurityException {
    return super.copyFileToTempDirectory(aUrl, aFilename);
  }

  protected File copyFileToTempDirectory(URL aUrl, final String aFilename)
    throws IOException, GeneralSecurityException {

    ConcurrentHashMap.Get getter = new ConcurrentHashMap.Get() {
      public Object getValue(Object aUrl)
       throws IOException, GeneralSecurityException {
        File tempFile = null;
        try {
          tempFile = SecureConfigFinder.this.superCopyFileToTempDirectory((URL)aUrl, aFilename);
        }
        catch (Exception sex) {
          _logger.warn("Unable to copy to temp directory: " + aFilename
    		   + ". Reason: " + sex);
      
          JarURLConnection juc = (JarURLConnection)((URL)aUrl).openConnection();

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
          //_file2URLs.remove(aUrl);

          if (tempFile.exists()) {
  	    // Delete the file, as the components may try to open the
            // file anyway.
	    tempFile.delete();
	    tempFile = null;
          }
        }
        return tempFile;
      }
    };

    File file = null;
    try {
      file = (File) m_filesProcessed.get(aUrl, getter);
    }
    catch (Exception e) {
      if (_logger.isErrorEnabled()) {
        _logger.error("Unexpected error while copying file: " + aUrl, e);
      }
    }
    return file;
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

  protected String getTmpBaseDirectoryName() {
    String s = System.getProperty("org.cougaar.workspace") + File.separator +
      "security" + File.separator + 
      "jarconfig" + File.separator +
      System.getProperty("org.cougaar.node.name");
    File f = new File(s);
    if (!f.exists()) {
      f.mkdirs();
    }
    return s;
  }


  /**
   * This input stream wraps the InputStream returned by the open()
   * method and checks that the client invokes the close() method.
   */
  public static class DebugInputStream
    extends InputStream
  {
    public static final int DELAY_BEFORE_WARN = 30000;
    private boolean _isClosed = false;
    private long _initTime;
    private Throwable _t;
    private InputStream _in;

    public DebugInputStream(InputStream in) {
      _in = in;
      _initTime = System.currentTimeMillis();
      _t = new Throwable();

      Runnable r = new Runnable() {
	  public void run() {
	    boolean done = false;
	    while (!done) {
	      try {
		Thread.sleep(DELAY_BEFORE_WARN);
	      }
	      catch (InterruptedException ex) {}
	      if (!_isClosed) {
		if (_logger.isWarnEnabled()) {
		  long now = System.currentTimeMillis();
		  _logger.warn("Stream status after "
			       + ((now - _initTime) / 1000) + "s: "
			       + _isClosed, _t);
		}
	      }
	      else {
		done = true;
	      }
	    }
	  }
	};
      Thread t = new Thread(r);
      t.start();
    }
    public int read() 
      throws IOException {
      return _in.read();
    }
    public void close()
      throws IOException {
      _isClosed = true;
      _in.close();
    }
  }

}
