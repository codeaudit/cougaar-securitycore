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

package test.org.cougaar.core.security.test.config;

import java.io.*;
import java.util.*;
import java.net.*;

import org.cougaar.util.ConfigFinder;

// Cougaar Security Services
import org.cougaar.core.security.config.SecureConfigFinder;

import org.w3c.dom.Document;
import junit.framework.*;
import org.apache.log4j.*;

public class SecureConfigFinderTest
  extends TestCase
{
  protected static final Category _logger =
  Category.getInstance(SecureConfigFinderTest.class);

  protected SecureConfigFinder _scf;

  public SecureConfigFinderTest(String name)
  {
    super(name);
  }

  /**
   * Quick unit test of the Secure Config Finder
   *  args[0] should be the name of a configuration file
   */
  public void setUp() {
    
  }

  public void testSecureConfigFinder() {
    String files[] = {"BootPolicy.ldm.xml", "cryptoPolicy.xml", "foo"};
    testFiles(files);
  }

  private void testFiles(String files[]) {
    Assert.assertNotNull(files);
    _scf = (SecureConfigFinder)ConfigFinder.getInstance();
    URL[] jarFiles = getJarFilesFromClassPath();
    for (int i = 0 ; i < jarFiles.length ; i++) {
      _scf.appendAndSearch(jarFiles[i], null);
    }
    // Search file. It should be found in the config path.
    testLocateFile(files);
    testOpen(files);
    testFind(files);
    testParseXMLConfigFile(files);
    // Search again same file. It should be found in cache.
    testLocateFile(files);
  }

  private URL[] getJarFilesFromClassPath() {
    ClassLoader cl = ClassLoader.getSystemClassLoader();
    int size = 0;
    URL[] jarFiles = null;
    if (cl != null) {
      if (cl instanceof URLClassLoader) {
	URLClassLoader ucl = (URLClassLoader) cl;
	jarFiles = ucl.getURLs();
      }
    }
    return jarFiles;
  }

  private void testLocateFile(String files[]) {
    for (int i = 0 ; i < files.length ; i++) {
      _logger.debug("Looking up file handle for: " + files[i]);
      try {
	File f = _scf.locateFile(files[i]);
	if (f.exists()) {
	  dumpFileContent(files[i], new FileInputStream(f), 4);
	}
	else {
	  _logger.warn("File content not available: " + files[i]);
	}
      }
      catch (Exception e) {
	_logger.warn("Unable to open file:" + files[i]);
      }
    }
  }

  private void testOpen(String files[]) {
    for (int i = 0 ; i < files.length ; i++) {
      _logger.debug("Looking up file InputStream for: " + files[i]);
      try {
	InputStream is = _scf.open(files[i]);
	dumpFileContent(files[i], is, 4);
      }
      catch (Exception e) {
	_logger.warn("Unable to open file:" + files[i]);
      }
    }
  }

  private void testFind(String files[]) {
    for (int i = 0 ; i < files.length ; i++) {
      _logger.debug("Looking up file URL: " + files[i]);
      try {
	_logger.debug(files[i] + " : " + _scf.find(files[i]));
      }
      catch (Exception e) {
	_logger.warn("Unable to find file: " + files[i]);
      }
    }
  }

  private void testParseXMLConfigFile(String files[]) {
    for (int i = 0 ; i < files.length ; i++) {
      _logger.debug("Parsing XML: " + files[i]);
      try {
	Document d = _scf.parseXMLConfigFile(files[i]);
	_logger.debug("Document:" + d);
      }
      catch (Exception e) {
	_logger.warn("Unable to parse XML file: " + files[i]);
      }
    }
  }

  private void dumpFileContent(String name, InputStream is, int maxLines) {
    _logger.debug("Dumping first " + maxLines + " lines of "
      + name);
    BufferedReader br =
      new BufferedReader(new InputStreamReader(is));
    String val = null;
    int lineCount = 0;
    try {
      while ((val = br.readLine()) != null && lineCount < maxLines) {
	_logger.debug(val);
	lineCount++;
      }
      br.close();
    }
    catch (Exception e) {
      _logger.warn("Unable to dump file content: " + name);
    }
  }
}
