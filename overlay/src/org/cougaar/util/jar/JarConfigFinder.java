/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

package org.cougaar.util.jar;

import java.io.IOException;
import java.io.File;
import java.io.FileFilter;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.net.URL;
import java.net.URI;
import java.net.URLConnection;
import java.net.JarURLConnection;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.cougaar.util.log.Logging;
import org.cougaar.util.log.Logger;
import org.cougaar.util.ConfigFinder;
import org.cougaar.util.Configuration;

/**
 * A configuration file finder that searches files in Jar files.
 *
 * Configuration files are searched as follows: 
 * The configuration path may contain URLs pointing to the following elements:
 *  - An plain-text file
 *  - A signed or unsigned jar file in a file system or available through
 *    an HTTP connection
 *  - A local directory
 * The configuration path is a semi-colon ordered list of these URL elements.
 * The search is performed by looking at the URL elements from left to right.
 * + If the element is a plain-text file and the name matches the requested file,
 *   the file is returned.
 * + If the element is a jar file, the JarConfigFinder attempts to locate
 *   a file in the jar file that matches the name of the requested file.
 *   The jar file can be opened in a file system or through an HTTP
 *   connection.
 * + If the element is a directory in a file system, the JarConfigFinder
 *   attempts to locate a matching (unsigned) file in that directory.
 *   The JarConfigFinder also looks up all jar files contained in that
 *   directory and tries to find a matching file in one of those jar files.
 *
 * If _jarFilesOnly is set to true, only files contained in JAR files will
 * be searched.

 * If the org.cougaar.config.signedOnly variable is set to true,
 * the SecureConfigFinder returns only files that have been signed.
 */
public class JarConfigFinder
  extends ConfigFinder
{
  /** A hashtable containing mappings between file names and their URLs.
   * This table caches the information once it has been found, either
   * in JAR files or regular files.
   */
  protected Map _file2URLs = new Hashtable();

  /** A list of URLs pointing to JAR files containing resource files.
   * Files requested by a client are searched in those jar files.
   */
  private List _jarFileCache = new ArrayList();

  /** A list of path to look for JAR files
   *  This list is initially populated by using the configuration
   *  from the constructor. It may be augmented by adding Jar files
   *  found in the config path
   */
  private List _configPathList;

  /** A directory to store files extracted from JAR files, so that we
   *  can return a File reference to the client.
   */
  private File _jarFileCacheDirectory;

  /** A directory to extract files from JAR files, before they are
   *  moved to the _jarFileCacheDirectory.
   */
  private File _tmpDirectory;

  private boolean _jarFilesOnly;

  public JarConfigFinder() {
    this(Configuration.getConfigPath(), Configuration.getDefaultProperties());
  }
  public JarConfigFinder(String path) {
    this(path, Configuration.getDefaultProperties());
  }
  public JarConfigFinder(String path, Map props) {
    this(null, path, props);
  }
  public JarConfigFinder(String module, String path) {
    this(module, path, Configuration.getDefaultProperties());
  }
  public JarConfigFinder(String module, String path, Map props) {
    super(module, path, props);
    createJarFileCacheDirectory();

    _configPathList = new ArrayList();
    _configPathList.addAll(getConfigPath());

    // Allow locating files in all files by default
    _jarFilesOnly = Boolean.valueOf
      (System.getProperty
       ("org.cougaar.util.jar.jarFilesOnly", "false")).booleanValue();

    if (getLogger().isDebugEnabled()) {
      getLogger().debug("jar Files only: " + jarFilesOnly());
      Iterator it = _configPathList.iterator();
      String s = "";
      while (it.hasNext()) {
        s = s + " - " + ((URL) it.next()).toString();
      }
      getLogger().debug("Config path:" + s);
    }

  }

  ////////////////////////////////////////////////////////////////////
  // BEGIN ConfigFinder overloaded methods

  /**
   * Locate a file.
   * In most cases, the parameter being passed is a file name,
   * but it could be a partial or complete URL.
   * @param aFileName - The name of a file being searched
   */
  public File locateFile(String aFilename) {
    if (getLogger().isDebugEnabled()) {
      getLogger().debug("locateFile:" + aFilename);
    }
    URL aUrl = resolveUrl(aFilename);
    if (aUrl == null) {
      return null;
    }
    if (getLogger().isDebugEnabled()) {
      getLogger().debug("Found:" + aUrl.toString());
    }
    File f = null;
    if (aUrl.getProtocol().startsWith("jar")) {
      // The file is in a Jar file. We cannot return a File handle
      // directly, so we copy the file in a temporary directory
      // copyFileToTempDirectory checks for invalid signatures.
      try {
	f = copyFileToTempDirectory(aUrl, aFilename);
      }
      catch (Exception e) {
	getLogger().warn("Unable to copy to temp directory: " + aFilename
		     + ". Reason: " + e);
      }
    }
    else {
      try {
	f = new File(new URI(aUrl.toString()));
      }
      catch (Exception e) {
	getLogger().warn("Unable to get file handle for " + aFilename);
      }
    }
    return f;
  }

  /**
   * Opens an InputStream to access the named file. The file is sought
   * in all the places specified in configPath.
   * @param aURL - The name of a file being searched
   * @throws IOException if the resource cannot be found.
   **/
  public InputStream open(String aURL)
    throws IOException {
    if (getLogger().isDebugEnabled()) {
      getLogger().debug("open:" + aURL);
    }
    URL aUrl = resolveUrl(aURL);
    if (getLogger().isDebugEnabled()) {
      getLogger().debug("Found:" + (aUrl != null ? aUrl.toString() : null));
    }
    if (aUrl == null) {
      throw new IOException("Resource cannot be found: " + aURL);
    }
    else {
      // The resolveUrl() method checks that the
      // signature was valid, so we do not check again here
      return aUrl.openStream();
    }
  }

  /**
   * Attempt to find the URL which would be opened by the open method.
   * Note that this must actually attempt to open the various URLs
   * under consideration, so this is <em>not</em> an inexpensive operation.
   * @param aURL - The name of a file being searched
   **/
  public URL find(String aURL)
    throws IOException {
    // The resolveUrl() method checks that the
    // signature was valid, so we do not check again
    URL theURL = resolveUrl(aURL);
    return theURL;
  }

  // END ConfigFinder overloaded methods
  ///////////////////////////////////////////////////////////////////

  /**
   * Resolve a logical reference to a URL
   * @param aFileName the name of a file to be resolved
   * @returns null if no file can be found at that location
   */
  protected URL resolveUrl(String aFileName) {
    URL theURL = null;

    if (getLogger().isDebugEnabled()) {
      getLogger().debug("Looking up " + aFileName + " in local cache ("
		    + _file2URLs.size() + " elements)");
    }
    // First, search in the cache
    theURL = (URL) _file2URLs.get(aFileName);
    if (theURL != null) {
      if (getLogger().isDebugEnabled()) {
	getLogger().debug("Found " + aFileName + " in local cache");
      }
    }
    else {
      // Second, search the file in the list of JAR files
      if (getLogger().isDebugEnabled()) {
	getLogger().debug("Looking up " + aFileName + " in Jar file list ("
		      + _jarFileCache.size() + " jar files)");
      }
      ListIterator it = _jarFileCache.listIterator();
      while (it.hasNext()) {
	JarFileInfo entry = (JarFileInfo) it.next();
	theURL = locateFileInJarFile(aFileName, entry);
	if (theURL != null) {
	  if (getLogger().isDebugEnabled()) {
	    getLogger().debug("Found " + aFileName + " in Jar file list");
	  }
	}
      }
    }

    if (theURL == null) {
      // Third, the list of JAR files may have not been updated yet.
      // Update the list of jar files by looking in the configPath and
      // finding jar files. Remove jar files from configPath as they
      // are added to _jarFileCache.
      if (getLogger().isDebugEnabled()) {
	getLogger().debug("Looking up " + aFileName + " in config path ("
		      + _configPathList.size() + " elements)");
      }
      ListIterator it = _configPathList.listIterator();
      while(it.hasNext() && (theURL == null)) {
	URL base = (URL) it.next();
	theURL = locateFileInPathElement(base, aFileName);
	// Remove from _configPathList, so that we don't look it
	// up again the next time we search.
	getLogger().debug("Removing " + base + " from path");
	it.remove();
	/*
	  for (int i = 0 ; i < _configPathList.size() ; i++) {
	  getLogger().debug(_configPathList.get(i).toString());
	  }
	*/
      }
    }

    // Verify the integrity of the input stream.
    try {
      verifyInputStream(theURL);
    }
    catch (Exception e) {
      // Do not return the URL if the integrity of the data could not
      // be verified.
      theURL = null;
    }
    return theURL;
  }

  /** Return a JarFile if the file is really a Jar file.
   *  Return null otherwise.
   */
  protected JarFile getJarFile(File aFile) {
    try {
      JarFile aJarFile = new JarFile(aFile);
      return aJarFile;
    }
    catch (Exception e) {
      // This is not a Jar file, or the file could not be read
      return null;
    }
  }

  protected void appendJarFiles(URL[] jarFiles) {
    for (int i = 0 ; i < jarFiles.length ; i++) {
      appendJarFile(jarFiles[i]);
    }
  }

  protected void createJarFileCacheDirectory() {
    // Create temporary directory to store files
    try {
      _jarFileCacheDirectory =
	new File(System.getProperty("org.cougaar.workspace") +
		 File.separator + "jarFileCache");
      deleteDirectory(_jarFileCacheDirectory);
      if (!_jarFileCacheDirectory.exists()) {
	_jarFileCacheDirectory.mkdirs();
      }

      _tmpDirectory =
	new File(System.getProperty("org.cougaar.workspace") +
		 File.separator + "tmp");
      deleteDirectory(_tmpDirectory);
      if (!_tmpDirectory.exists()) {
	_tmpDirectory.mkdirs();
      }
    }
    catch (Exception e) {
      getLogger().warn("Unable to create temporary directory", e);
    }
  }

  private void deleteDirectory(File file) {
    if (file == null || !file.exists()) {
      return;
    }
    if (file.isFile()) {
      file.delete();
    }
    else {
      File subfiles[] = file.listFiles();
      for (int i = 0 ; i < subfiles.length ; i++) {
	deleteDirectory(subfiles[i]);
      }
    }
  }

  /**
   * Copy a file contained in a Jar file so that it can be opened using
   * a <class>File</class> handle.
   */
  protected File copyFileToTempDirectory(URL aUrl, String aFilename)
    throws IOException, GeneralSecurityException {
    if (getLogger().isDebugEnabled()) {
      getLogger().debug("Copying " + aUrl + " to temp directory");
    }

    File tempFile = 
      File.createTempFile("tmpFile", ".tmp", _tmpDirectory);
    FileOutputStream fos = new FileOutputStream(tempFile);
    JarURLConnection juc = (JarURLConnection)aUrl.openConnection();
    InputStream is = juc.getInputStream();
    int v = 0;
    while ((v = is.read()) != -1) {
      fos.write(v);
    }
    fos.close();
    is.close();
      
    File newFile = new File(_jarFileCacheDirectory, aFilename);
    boolean isRenamed = tempFile.renameTo(newFile);
    if (isRenamed) {
      return newFile;
    }
    else {
      // Remove the temp file
      tempFile.delete();
      return null;
    }
  }

  protected JarFileInfo appendJarFile(URL jarFile) {
    try {
      if (!jarFile.getProtocol().equals("jar")) {
	// The multi-parameter URL constructor does not like
	// the "jar:file" protocol, but it works with a one-parameter
	// constructor
	String s = "jar:" + jarFile.getProtocol() + ":" +
	  jarFile.getHost();
	if (jarFile.getPort() != -1) {
	  s = s + ":" + jarFile.getPort();
	}
	s = s + jarFile.getPath() + "!/";
	jarFile = new URL(s);
	if (getLogger().isDebugEnabled()) {
	  getLogger().debug("Append Jar File: " + jarFile.toString());
	}
      }

      JarFileInfo entry = new JarFileInfo(jarFile);

      verifyJarFile(entry.getJarFile());
     
      _jarFileCache.add(entry);
      return entry;
    }
    catch (Exception e) {
      getLogger().warn("Unable to add entry: " + jarFile.toString(), e);
      return null;
    }
  }

  protected URL locateFileInJarFile(String aFileName, JarFileInfo entry) {
    URL theURL = null;
    if (entry == null) {
      return null;
    }
    if (getLogger().isDebugEnabled()) {
      getLogger().debug("Locate file " +
			aFileName + " in " + entry.getJarFileURL()
			+ " Processed: " + entry.isJarFileProcessed());
    }
    if (entry.isJarFileProcessed()) {
      // The JAR file has already been processed. Therefore,
      // we should have already looked in the cache for that Jar file.
      return null;
    }
    JarFile jarFile = entry.getJarFile();
    Enumeration enum = jarFile.entries();
    while (enum.hasMoreElements()) {
      JarEntry jarEntry = (JarEntry) enum.nextElement();
      if (jarEntry.isDirectory()) {
	continue;
      }
      String entryFullName = jarEntry.getName();
      File aFile = new File(entryFullName);
      String entryName = aFile.getName();

      String s = entry.getJarFileURL().toString() + entryFullName;
      try {
	URL aURL = new URL(s);
	addFileEntryToCache(entryName, aURL);
	if (aFileName.equals(entryName)) {
	  theURL = aURL;
	}
      }
      catch (Exception e) {
	getLogger().warn("Unexpected exception: ", e);
      }
    }
    entry.setJarFileProcessed(true);
    return theURL;
  }
  
  /**
   * Check the integrity of a jar file. Do nothing in the base
   * implementation.
   */
  protected void verifyJarFile(JarFile aJarFile)
    throws GeneralSecurityException {
  }

  /**
   * Verify the integrity of the data contained at a URL.
   * Some integrity issues might be discovered late when reading
   * an input stream. For example, digest errors are discovered
   * when the entire stream has been read. This gives the opportunity
   * for a secure file finder to verify the data before the stream
   * is returned to the caller.
   *
   * Does nothing in the default implementation, but should typically be
   * defined in a derived class.
   * @param aURL the URL to check.
   * @exception IOException if an IO Exception occurs while opening the stream
   * @exception GeneralSecurityException if there was a problem while checking
   *                the integrity of the input stream.
   */
  protected void verifyInputStream(URL aURL)
    throws IOException, GeneralSecurityException {
  }

  private void addFileEntryToCache(String aFileName, URL aURL) {
    if (!_file2URLs.containsKey(aFileName)) {
      // getLogger().debug("Adding mapping: " + aFileName + "<=>"
      // + aURL.toString());
      _file2URLs.put(aFileName, aURL);
    }
  }

  /**
   * @param base - The path element where to search files.
   * @param aFileName - The name of a file to search.
   *
   * If aFileName is null, then no search is performed. The path
   * element is still added to the cache.
   */
  protected URL locateFileInPathElement(URL base, String aFileName) {
    URL theURL = null;
    if (getLogger().isDebugEnabled()) {
      getLogger().debug("locateFileInPathElement:" + aFileName
			+ " in " + base.toString());
    }
    if (base.getProtocol().equals("file") ||
	base.getProtocol().equals("jar:file")) {
      theURL = locateFileInFileElement(base, aFileName);
    }
    else if (base.getProtocol().equals("http")) {
      theURL = locateFileInHttpElement(base, aFileName);
    }
    return theURL;
  }

  protected URL locateFileInFileElement(URL base, String aFileName) {
    URL theURL = null;
    File aFile = new File(base.getFile());
    if (aFile.exists()) {
      if (aFile.isFile()) {
	// This is a file. Return it if there is a match
	// and it is ok to return unsigned jar files.
	JarFile aJarFile = getJarFile(aFile);
	if (aJarFile == null) {
	  // This is not a Jar file, or the file could not be read
	  if (!jarFilesOnly()) {
	    if (acceptUnsignedFiles() && aFileName != null) {
	      try {
		addFileEntryToCache(aFile.getName(), aFile.toURL());
		// Is there a match?
		if (aFileName.equals(aFile.getName())) {
		  theURL = aFile.toURL();
		}
	      }
	      catch (Exception e) {
		getLogger().warn("Unable to get URL for " + aFile.getPath());
	      }
	    }
	  }
	}
	else {
	  // This is a Jar file.
	  // Add the new jar file to the list of jar files.
	  try {
	    JarFileInfo entry = appendJarFile(aFile.toURL());
	    if (aFileName != null) {
	      theURL = locateFileInJarFile(aFileName, entry);
	    }
	  }
	  catch (Exception e) {
	    getLogger().warn("Unable to get URL for " + aFile.getPath());
	  }
	}
      }
      else if (aFile.isDirectory()) {
	// This is a directory. Attempt to find jar files
	// in that directory.

	File jarFiles[] = aFile.listFiles(new FileFilter() {
	    public boolean accept(File pathname) {
	      return pathname.getName().endsWith(".jar");
	    }
	  });
	for (int i = 0 ; i < jarFiles.length ; i++) {
	  JarFile aJar = getJarFile((File)jarFiles[i]);
	  if (aJar != null) {
	    // Add the new jar file to the list of jar files.
	    try {
	      JarFileInfo entry = appendJarFile(jarFiles[i].toURL());
	      if (aFileName != null) {
		URL aURL = locateFileInJarFile(aFileName, entry);
		if (aURL != null && theURL == null) {
		  theURL = aURL;
		}
	      }
	    }
	    catch (Exception e) {
	      getLogger().warn("Unable to get URL for " + jarFiles[i]);
	    }
	  }
	}
	// Also try to find simple files in that directory
	// (if allowed by the configuration)
	if (!jarFilesOnly()) {
	  if (acceptUnsignedFiles()) {
	    File files[] = aFile.listFiles(new FileFilter() {
		public boolean accept(File pathname) {
		  return true;
		}
	      });
	    for (int i = 0 ; i < files.length ; i++) {
	      try {
		File confFile = files[i];

		addFileEntryToCache(confFile.getName(), confFile.toURL());
		// Is there a match?
		if (aFileName.equals(confFile.getName())) {
		  theURL = confFile.toURL();
		}
	      }
	      catch (Exception e) {
		getLogger().warn("Unable to get URL for " + aFile.getPath());
	      }
	    }
	  }
	}
      }
    }
    if (getLogger().isDebugEnabled()) {
      getLogger().debug("Searched " + aFileName
	+ " under " + base.toString() + ". Found: " + theURL);
    }
    return theURL;
  }

  protected URL locateFileInHttpElement(URL base, String aFileName) {
    URL theURL = null;
    // First, try to open the file as a Jar URL connection
    try {
      JarURLConnection juc = (JarURLConnection)base.openConnection();
      JarFile jf = juc.getJarFile();
      // This is a Jar file.
      // Add the new jar file to the list of jar files.
      JarFileInfo entry = appendJarFile(juc.getURL());
      if (aFileName != null) {
	theURL = locateFileInJarFile(aFileName, entry);
      }
    }
    catch (Exception e) {
      // That wasn't a Jar file
    }
    if (theURL == null) {
      // Process the given URL as a standard file
      if (aFileName.equals(base.getFile())) {
	theURL = base;
      }
    }
    return theURL;
  }

  protected boolean acceptUnsignedFiles() {
    return true;
  }

  protected boolean jarFilesOnly() {
    return _jarFilesOnly;
  }
}
