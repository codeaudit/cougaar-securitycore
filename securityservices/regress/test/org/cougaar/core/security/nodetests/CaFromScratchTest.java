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

package test.org.cougaar.core.security.nodetests;

import java.io.*;
import java.util.*;
import java.util.regex.*;
import junit.framework.*;

public class CaFromScratchTest
{
  private String nodeName;

  /** Tests

   *  - Restart CA
   *  - Create CA key
   *  - End test

   *  - Restart CA
   *  - List CA keys
   *  - List certificates
   *  - End test
   *
   */

  /*
   *  - Remove $COUGAAR_WORKSPACE/security/keystores/caNode directory
   *  - Remove $COUGAAR_WORKSPACE/log4jlogs/caNode.log log file
   *  - Start CA.
   *  - End test
   */
  public void runCaFromScratchTest(String arg) {
    nodeName = arg;
    String path = System.getProperty("org.cougaar.workspace")
      + File.separator + "security" + File.separator + "keystores"
      + File.separator + nodeName;
    File file = new File(path);
    System.out.println("Removing files under " + path);

    removeRecursively(file);
  }

  /** Remove a folder and subfolders
   */
  private void removeRecursively(File file) {
    if (file.isFile()) {
      boolean isDeleted = file.delete();
      System.out.println("Deleting file " + file.getPath() + ": " + isDeleted);
      return;
    }
    else if (file.isDirectory()) {
      File files[] = file.listFiles();
      for (int i = 0 ; i < files.length ; i++) {
	removeRecursively(files[i]);
      }
      // Now remove the directory
      boolean isDeleted = file.delete();
      System.out.println("Deleting directory " + file.getPath() + ": " + isDeleted);
    }
  }

  /** Copy the CA certificate keystore to $CIP/configs/security. */
  public void installCaCertificateKeystore(String nodeName) {
    System.out.println("Copying CA keystore file");

    String path1 = System.getProperty("org.cougaar.workspace")
      + File.separator + "security" + File.separator + "keystores"
      + File.separator + nodeName + File.separator + "keystore-CONUS-RSA";
    File origin = new File(path1);

    // Extract last path element of org.cougaar.config.path and copy
    // the keystore file to that path.
    String path2 = System.getProperty("org.cougaar.install.path");
    path2 = path2 + File.separator + "configs" + File.separator
      + "security" + File.separator + "keystore-CA-JunitTest";
    File dest = new File(path2);
    copyFile(origin, dest);
  }

  private void copyFile(File origin, File dest) {
    System.out.println("Copying file " + origin.getPath()
		       + " to " + dest.getPath());
    try {
      BufferedInputStream bis =
	new BufferedInputStream(new FileInputStream(origin));
      BufferedOutputStream bos =
	new BufferedOutputStream(new FileOutputStream(dest));
      int i;
      while ((i = bis.read()) != -1) {
	bos.write(i);
      }
    }
    catch (IOException e) {
      System.out.println("Unable to copy keystore file");
      Assert.fail("Unable to copy keystore file from " + origin.getPath()
	+ " to " + dest.getPath());
    }
  }

}
