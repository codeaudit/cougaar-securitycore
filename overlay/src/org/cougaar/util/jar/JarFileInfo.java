/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software Inc
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

import java.net.JarURLConnection;
import java.util.jar.JarFile;
import java.net.URL;

public class JarFileInfo {
  /** The URL of the Jar file
   */
  private URL _theJarFileUrl;

  /** A JarFile reference to the JAR file
   */
  private JarFile _theJarFile;

  /** True if all the file names in the jar files have been processed and stored
   *  in the cache.
   */
  private boolean _isProcessed;

  public JarFileInfo(URL aUrl)
    throws java.io.IOException {
    _theJarFileUrl = aUrl;
    JarURLConnection juc =
      (JarURLConnection)_theJarFileUrl.openConnection();
    _theJarFile = juc.getJarFile();
    _isProcessed = false;
  }

  public URL getJarFileURL() {
    return _theJarFileUrl;
  }
  public JarFile getJarFile() {
    return _theJarFile;
  }
  public boolean isJarFileProcessed() {
    return _isProcessed;
  }
  public void setJarFileProcessed(boolean value) {
    _isProcessed = value;
  }
}
