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
import javax.naming.*;
import javax.naming.directory.*;

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
  public void runCaFromScratchTest(String nodeName, String ldapURL) {
    this.nodeName = nodeName;
    String path = System.getProperty("org.cougaar.workspace")
      + File.separator + "security" + File.separator + "keystores"
      + File.separator + nodeName;
    File file = new File(path);
    System.out.println("Removing files under " + path);

    removeRecursively(file);

    // Remove LDAP entries from LDAP directory
    deleteLdapSubtree(ldapURL);    
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
      bis.close();
      bos.close();
    }
    catch (IOException e) {
      System.out.println("Unable to copy keystore file");
      Assert.fail("Unable to copy keystore file from " + origin.getPath()
	+ " to " + dest.getPath());
    }
  }

  protected static String CONTEXT_FACTORY = 
    "com.sun.jndi.ldap.LdapCtxFactory";

  public void deleteLdapSubtree(String aURL) {
    try {
      DirContext context;

      String attr = null;
      int slash = aURL.lastIndexOf("/");
      int comma = aURL.indexOf(",");
      if (slash != -1 && comma != -1) {
	attr = aURL.substring(slash + 1, comma);
	aURL = aURL.substring(0,slash + 1) + aURL.substring(comma+1);
      }

      Hashtable env = new Hashtable();
      env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
      env.put(Context.PROVIDER_URL, aURL);
      
      context=new InitialDirContext(env);
      context.addToEnvironment(Context.SECURITY_PRINCIPAL,
			       "cn=manager, dc=cougaar, dc=org");
      context.addToEnvironment(Context.SECURITY_CREDENTIALS, "secret");

      NamingEnumeration ne = context.list("dc=junittest");
      deleteLdapRecursively(context, ne, ", dc=junittest");
      ne.close();
    }
    catch (Exception e) {
      System.out.println("Unable to set directory service URL: " + e);
      e.printStackTrace();
    }
  }

  private void deleteLdapRecursively(Context context, NamingEnumeration ne, String top)
    throws Exception {
    while (ne.hasMore()) {
      NameClassPair name = (NameClassPair) ne.next();
      //System.out.println("Class: " + name.getClass().getName() + " - " + name.getName() + " / " + name.getClassName());
      // Remove entries
      NamingEnumeration namingEnum = context.list(name.getName() + top);

      if (namingEnum.hasMore()) {
	//System.out.println("Deleting recursively");
	deleteLdapRecursively(context, namingEnum, top);
      }
      else {
	DirContext dc = (DirContext) context.lookup(name.getName() + top);
	String subname = dc.getNameInNamespace();
	//System.out.println("Subname: " + subname);
	context.destroySubcontext(name.getName() + top);
      }
    }
  }
}
