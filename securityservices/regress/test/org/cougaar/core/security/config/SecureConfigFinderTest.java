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

package test.org.cougaar.core.security.config;

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
    String knownFiles[] = {"BootPolicy.ldm.xml", "cryptoPolicy.xml"};
    String unknownFiles[] = {"foo.ldm.xml", "bar.xml"};
    testFiles(knownFiles, true);
    testFiles(unknownFiles, false);
  }

  /** 
   * @param files - A list of files to be found in JAR files.
   * @param shouldExist - Whether the files should be found in the path or not.
   */
  private void testFiles(String files[], boolean shouldExist) {
    Assert.assertNotNull(files);
    Assert.assertTrue(files.length > 0);
    _scf = (SecureConfigFinder)ConfigFinder.getInstance();
    Assert.assertNotNull(_scf);
    URL[] jarFiles = getJarFilesFromClassPath();
    _scf.appendUrlSearchPath(jarFiles);

    // Search file. It should be found in the config path.
    testLocateFile(files, shouldExist);
    testOpen(files, shouldExist);
    testFind(files, shouldExist);
    testParseXMLConfigFile(files, shouldExist);
    // Search again same file. It should be found in cache.
    testLocateFile(files, shouldExist);
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

  private void testLocateFile(String files[], boolean shouldExist) {
    for (int i = 0 ; i < files.length ; i++) {
      _logger.debug("Looking up file handle for: " + files[i]);
      try {
	File f = _scf.locateFile(files[i]);
	boolean exists = f.exists();
	if (shouldExist) {
	  Assert.assertTrue("File does not exist but it should:" + files[1], exists);
	}
	else {
	  Assert.assertTrue("File exists but it should not:" + files[1], !exists);
	}
	if (exists) {
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

  private void testOpen(String files[], boolean shouldExist) {
    for (int i = 0 ; i < files.length ; i++) {
      _logger.debug("Looking up file InputStream for: " + files[i]);
      try {
	InputStream is = _scf.open(files[i]);
	dumpFileContent(files[i], is, 4);
	if (!shouldExist) {
	  Assert.fail("File should not exist:" + files[i]);
	}
      }
      catch (Exception e) {
	_logger.warn("Unable to open file:" + files[i]);
	if (shouldExist) {
	  Assert.fail("Unable to open file:" + files[i]);
	}
      }
    }
  }

  private void testFind(String files[], boolean shouldExist) {
    for (int i = 0 ; i < files.length ; i++) {
      _logger.debug("Looking up file URL: " + files[i]);
      try {
	URL aURL = _scf.find(files[i]);
	_logger.debug(files[i] + " : " + aURL);
	if (!shouldExist && aURL != null) {
	  Assert.fail("File should not exist:" + files[i]);
	}
	if (shouldExist && aURL == null) {
	  Assert.fail("File should have been found:" + files[i]);
	}
      }
      catch (Exception e) {
	_logger.warn("Unable to find file: " + files[i]);
	if (shouldExist) {
	  Assert.fail("File should have been found:" + files[i]);
	}
     }
    }
  }

  private void testParseXMLConfigFile(String files[], boolean shouldExist) {
    for (int i = 0 ; i < files.length ; i++) {
      _logger.debug("Parsing XML: " + files[i]);
      try {
	Document d = _scf.parseXMLConfigFile(files[i]);
	_logger.debug("Document:" + d);
	if (!shouldExist && d != null) {
	  Assert.fail("File should not exist:" + files[i]);
	}
	if (shouldExist && d == null) {
	  Assert.fail("File should have been found:" + files[i]);
	}
      }
      catch (Exception e) {
	_logger.warn("Unable to parse XML file: " + files[i]);
	if (shouldExist) {
	  Assert.fail("File should have been found:" + files[i]);
	}
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
