/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */

package org.cougaar.core.security.test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Iterator;
import java.util.ArrayList;
import java.net.URL;
import java.net.JarURLConnection;
import java.net.MalformedURLException;

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.util.ConfigFinder;

import EDU.oswego.cs.dl.util.concurrent.CountDown;

public class TestSecureConfigFinder
  extends ComponentPlugin
{
  private LoggingService _log;
  private ConfigFinder _configFinder;

  /**
   * We try to open this file in the tmp directory using an
   * absolute path name. The file is not in a signed jar file,
   * but we have an exception list for files in the /tmp
   * directory.
   */
  private static final String _tmpFile = "/tmp/nodeConf.xml";

  /**
   * We try to open this file using an absolute path name.
   * The file is not in a signed jar file.
   */
  private static String _absoluteNodeConf = null;

  /**
   * We try to open this file using a relative path.
   * The file in not in a signed jar file.
   */
  private static String _cfgCommonNodeConf = null;

  /**
   * We try to open this file using a relative path.
   * The file is in a signed jar file.
   */
  private static String _cfgInJarFile = "BootPolicyList.ini";

  private static URL _cfgInJarFileUrl = null;

  // The size of a test file
  private static int FILE_SIZE = 5000;

  // Number of threads to launch concurrently
  private static int MAX_THREADS = 100;

  public TestSecureConfigFinder() {
    _cfgCommonNodeConf = System.getProperty("org.cougaar.install.path")
      + File.separator + "configs" + File.separator + "common"
      + File.separator + "nodeConfXYZ.xml";

    _absoluteNodeConf = System.getProperty("org.cougaar.workspace")
      + File.separator + "nodeConf123.xml";

  }

  protected void setupSubscriptions() {
    _log = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    _configFinder = getConfigFinder();

    if (_log.isDebugEnabled()) {
      _log.debug("setupSubscriptions");
    }

    try {
      _cfgInJarFileUrl =
	new URL("jar:file:" +
		System.getProperty("org.cougaar.install.path")
		+ "/configs/security/securityservices_config.jar" +
		"!common/BootPolicyList.ini");
    }
    catch (MalformedURLException e) {
      _log.warn("Unable to construct cfgInJarFileUrl");
    }

    TestCase tc = new TestCase();
    tc.start();
  }

  protected void execute() {
  }

  private class TestCase extends Thread {
    public void run() {
      singleRun();

      deleteFile(_cfgCommonNodeConf);
      File f = new File(_cfgCommonNodeConf);
      createFile(_cfgCommonNodeConf);
      concurrentAccess(f.getName(), false, null);

      concurrentAccess(_cfgInJarFile, true, null);
    }

    /**
     * Attempt to acces inexistent file,
     * Then file which is not in a Jar file
     * Then file which is in a jar file
     */
    private void singleRun() {
      if (_log.isInfoEnabled()) {
	_log.info("Single Run");
      }

      // Try to open inexistent file
      deleteFile(_absoluteNodeConf); // With absolute path
      tryToOpenFile(_absoluteNodeConf, null, false, null);

      File f = new File(_cfgCommonNodeConf);

      /*
      deleteFile(_cfgCommonNodeConf); // With relative path
      tryToOpenFile(f.getName(), null, false);
      */

      // Try to open existing file
      createFile(_tmpFile); // With absolute path
      tryToOpenFile(_tmpFile, null, true, null);

      // Try to open existing files
      createFile(_absoluteNodeConf); // With absolute path
      tryToOpenFile(_absoluteNodeConf, null, false, null);

      createFile(_cfgCommonNodeConf); // With relative path
      tryToOpenFile(f.getName(), null, false, null);

      try {
	// Open reference file
	JarURLConnection jc = (JarURLConnection)_cfgInJarFileUrl.openConnection();
	tryToOpenFile(_cfgInJarFile, null, true, jc.getInputStream());
	jc.getInputStream().close();
      }
      catch (IOException e) {
	_log.warn("Unable to open reference file");
      }
    }

    private void concurrentAccess(final String fileName,
				  final boolean shouldBeFound,
				  final InputStream referenceStream) {
      if (_log.isInfoEnabled()) {
	_log.info("Starting concurrent access of " + fileName);
      }
      final CountDown cd = new CountDown(MAX_THREADS);

      ArrayList al = new ArrayList();
      for (int i = 0 ; i < MAX_THREADS ; i++) {
	Thread t = new Thread(new Runnable() {
	    public void run() {
	      tryToOpenFile(fileName, cd, shouldBeFound, referenceStream);
	    }
	  });
	al.add(t);
      }
      Iterator it = al.iterator();
      while (it.hasNext()) {
	Thread t = (Thread) it.next();
	t.start();
      }
      // Wait for all thread to finish
      try {
	cd.acquire();
      }
      catch (InterruptedException e) {
	if (_log.isWarnEnabled()) {
	  _log.warn("Interrupted Exception: " + fileName);
	}
      }
      if (_log.isInfoEnabled()) {
	_log.info("Done with concurrent access of " + fileName);
      }
    }
  }

  private void deleteFile(String fileName) {
    File tmpFile = new File(fileName);
    try {
      if (tmpFile.exists()) {
	tmpFile.delete();
      }
    }
    catch (Exception e) {
      if (_log.isWarnEnabled()) {
	_log.warn("Error while trying to delete file: " + fileName);
      }
    }
  }

  private void createFile(String fileName) {
    File file = new File(fileName);

    try {
      file.createNewFile();
      FileOutputStream fos = new FileOutputStream(file);
      for (int i = 0 ; i < FILE_SIZE ; i++) {
	fos.write(i % 256);
      }
      fos.close();
    }
    catch (Exception e) {
      if (_log.isWarnEnabled()) {
	_log.warn("Error while creating file" , e);
      }
    }
  }

  /** Check that the content of the file is the same as what
   * was written in the createFile() method.
   */
  private boolean checkFile(InputStream is, String fileName) {
    int val = 0;
    try {
      for (int i = 0 ; i < FILE_SIZE ; i++) {
	val = is.read();
	if (val != (i % 256)) {
	  if (_log.isWarnEnabled()) {
	    _log.warn("File content does not match. Found "
		      + val + " - Should be " + i
		      + " at pos " + i + " - " + fileName);
	  }
	  return false;
	}
      }
      // Attempt to read one more byte, but it should be the EOF
      if (is.read() != -1) {
	if (_log.isWarnEnabled()) {
	  _log.warn("File size does not match:" + fileName);
	}
	return false;
      }
    }
    catch (IOException e) {
      if (_log.isWarnEnabled()) {
	_log.warn("Unable to verify file: " + fileName);
      }
      return false;
    }
    return true;
  }

  private void tryToOpenFile(String fileName,
			     CountDown cd,
			     boolean shouldBeFound,
			     InputStream referenceStream) {
    InputStream is = null;
    // Try to read a file with an absolute path
    try {
      is = _configFinder.open(fileName);

      if (is != null) {
	if (shouldBeFound) { // The file has been found
	  if (referenceStream != null) {
	    StreamComparator sc =
	      new StreamComparator(referenceStream, is);
	    sc.compare();
	  }
	  else if (checkFile(is, fileName)) {
	    if (_log.isDebugEnabled()) {
	      _log.debug("Test passed: " + fileName);
	    }
	  }
	}
	else { // The file should not have been found
	  if (_log.isErrorEnabled()) {
	    _log.error("File should not have been found: " + fileName);
	  }
	}
	try {
	  is.close();
	}
	catch (Exception e) {
	  if (_log.isErrorEnabled()) {
	    _log.error("Unable to close file: " + fileName);
	  }
	}
      }
      else {
	if (shouldBeFound) { // The file should have been found
	  if (_log.isErrorEnabled()) {
	    _log.error("File should have been found: " + fileName);
	  }
	}
	else { // The file has not been found (ok)
	  if (_log.isDebugEnabled()) {
	    _log.debug("Test passed - File not found: " + fileName);
	  }
	}
      }
    }
    catch (IOException e) {
      if (shouldBeFound) { // The file should have been found
	if (_log.isWarnEnabled()) {
	  _log.warn("Error while trying to access file: " + fileName);
	}
      }
      else { // The file has not been found (ok)
	if (_log.isDebugEnabled()) {
	  _log.debug("Test passed - File not found: " + fileName);
	}
      }
    }
    if (cd != null) {
      cd.release();
    }
  }

  private class StreamComparator {
    private InputStream _is1;
    private InputStream _is2;
    public StreamComparator(InputStream is1, InputStream is2) {
      _is1 = is1;
      _is2 = is2;
    }

    public boolean compare() {
      int count = 0;
      boolean success = true;
      int b1 = 0, b2 = 0;
      try {
	while ( (b1 = _is1.read()) != -1 ) {
	  b2 = _is2.read();
	  if ((b2 == -1) || (b2 != b1)) {
	    if (_log.isWarnEnabled()) {
	      _log.warn("Content does not match - b1=" + b1
			+ " - b2=" + b2 + " at pos=" + count);
	    }
	    success = false;
	    break;
	  }
	  count++;
	}
	b2 = _is2.read();
      }
      catch (IOException e) {
	_log.warn("Unable to compare files");
      }
      if (b2 != -1) {
	if (_log.isWarnEnabled()) {
	  _log.warn("Content does not match - b2 stream longer than b1");
	}
	success = false;
      }
      
      if (success) {
	if (_log.isDebugEnabled()) {
	  _log.debug("Compare successfull");
	}
      }
      return success;
    }
  }
}
