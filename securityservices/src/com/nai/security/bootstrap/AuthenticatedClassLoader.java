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

package com.nai.security.bootstrap;

import java.lang.*;
import java.util.jar.*;
import java.util.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.net.*;

public class AuthenticatedClassLoader extends URLClassLoader {
  private static int loudness = 0;
  private static final List exclusions = new ArrayList();
  private static HashSet suspiciousClasses = new HashSet();
  protected static Hashtable loadedClasses = new Hashtable();

  static {
    String sdebug = System.getProperty("org.cougaar.core.security.bootstrapper.loud");
    if ("true".equals(sdebug)) {
      loudness = 1;
    } else if ("shout".equals(sdebug)) {
      loudness = 2;
    } else if ("false".equals(sdebug)) {
      loudness = 0;
    }

    // Using a list of excluded package names is a JDK1.1 mechanism
    // that does not follow the class loader delegation hierarchy.
    // Needs to be fixed.
    exclusions.add("java.");
    exclusions.add("javax.");
    // SUN JCE 1.2.1 provider won't load if com.sun is added to the list
    // of exclusions.
    exclusions.add("com.sun.");
    exclusions.add("sun.");
    exclusions.add("net.jini.");
    String s = System.getProperty("org.cougaar.bootstrapper.exclusions");
    if (s != null) {
      List extras = explode(s, ':');
      if (extras != null) {
	exclusions.addAll(extras);
      }
    }
    
    if (loudness > 0) {
      Object[] excluded = exclusions.toArray();
      System.out.print("Excluded packages are: " );
      for (int i=0; i<excluded.length; i++)
        System.out.print(" ( " + excluded[i]  + " ) ");
      System.out.println("");
    }
  }

  protected static SecurityManager sm = System.getSecurityManager();
  protected static CertificateVerifier certVerifier = new CertificateVerifier();

  protected JarEntry theEntry;
  protected JarFile theFile;

  public AuthenticatedClassLoader(URL[] trustedURLs){
    super(trustedURLs);
    if (loudness > 0) {
      for (int i=0 ; i < trustedURLs.length ; i++) {
	System.out.println("Trusted URL: " + trustedURLs[i]);
      }
    }
  }
        
  /** parse java property */
  static final List explode(String s, char sep) {
    ArrayList v = new ArrayList();
    int j = 0;                  //  non-white
    int k = 0;                  // char after last white
    int l = s.length();
    int i = 0;
    while (i < l) {
      if (sep==s.charAt(i)) {
	// is white - what do we do?
	if (i == k) {           // skipping contiguous white
	  k++;
	} else {                // last char wasn't white - word boundary!
	  v.add(s.substring(k,i));
	  k=i+1;
	}
      } else {                  // nonwhite
	// let it advance
      }
      i++;
    }
    if (k != i) {               // leftover non-white chars
      v.add(s.substring(k,i));
    }
    return v;
  }


  /** the class will not be loaded by this class loader if 
      true is returned
  */
  private boolean excludedP(String classname) {
    int l = exclusions.size();
    for (int i = 0; i<l; i++) {
      String s = (String)exclusions.get(i);
      if (classname.startsWith(s))
	return true;
    }
    return false;
  }


  /** calls findClass(String name) throws ClassNotFoundException of URLClassLoader.java
   */
  protected Class findClass(String classname) throws ClassNotFoundException {
    Class c = null;
    try {
      c = super.findClass(classname);             
    } catch (ClassNotFoundException e) {
      //catch exception silently due to the fact that multiple property group classes
      //are currently specified without their fully qualified path in the .ini files
      //and are later looked up in multiple packages until found
    }
    if (loudness > 0) {
      printPolicy(c);
    }
    return c;
  }

  /** helper method that checks whether we're allowed to 
      access the specified class (in accordance with java policy)
  */
  protected boolean checkPackageAccess(String classpath) throws SecurityException {
    if (sm != null) {
      String pkg = getPackageName(classpath);
      if (pkg != null) {
	sm.checkPackageAccess(pkg);
      }
    }
    return true;
  }


  /** helper method to extract package name */
  protected String getPackageName(String name) {
    int i = name.lastIndexOf('.');
    if (i != -1) {
      return name.substring(0, i);
    }else return null;
  }


  /** check if the class has already been loaded by this class loader */
  protected Class findLoaded(String classname) {
    return (Class)loadedClasses.get(classname);
  }


  /** check if this classloader has previously tried to load this class
      but did not find it among its trusted classes
  */
  protected boolean findSuspicious(String classname) {
    return suspiciousClasses.contains(classname);
  }

  /** add to the local cache of loaded or suspicious classes */
  protected void saveLocally(Class c, String name) {
    if (c == null) {
      suspiciousClasses.add(name);
    }
    else loadedClasses.put(name, c);
  }

  /** this method overrides default functionality provided by the java.lang.URLClassLoader */
  protected Class loadClass(String name, boolean resolve) 
    throws SecurityException, ClassNotFoundException {       

    /* Search for classes in the following order:
       1) Look if class has previously been loaded.
       2) Delegate to parent class loader.
       3) Call find class.
    */
    Class c = null;
    try {
      c = findLoaded(name);
      if (c == null) {   //class has not yet been loaded by this classloader
	if (!findSuspicious(name)) {  
	  /* let this class loader handle the class unless the class belongs
	     to the list of standard packages */ 

	  //throws a SecurityException if the calling thread is not allowed to access the package
	  //specified by the argument.
	  checkPackageAccess(name); 
	  if (!excludedP(name)) {
	    c = findClass(name);
	    saveLocally(c, name);
	  }
	  else {  //let the parent class loader handle this one
	    ClassLoader parent = getParent();
	    if (parent == null) parent = getSystemClassLoader();
	    //System.out.println("About to let the parent load class " + name);
	    try {
	      c = parent.loadClass(name);
	    } catch (ClassNotFoundException e) {
	      /* If class is not found by the system class loader, try looking for it with
		 AuthenticatedClassLoader.  The reason for this is: j2ee.jar file is located
		 in $COUGAAR_INSTALL_PATH/sys directory but is not in the runtime classpath.
		 Thus, classes that start with javax and are located in j2ee.jar cannot be found by the
		 SystemClassLoader but will be found by the AuthenticatedClassLoader if j2ee.jar 
		 has been signed by a trusted entity. 
	      */
	      c = findClass(name);
	      saveLocally(c, name);
	    }//end else
	  }
	}
	//else System.out.println("FOUND IN SUSPICIOUS");
      }

      if (resolve) {
	if (c != null)
	  resolveClass(c);
      }

    }catch(Exception e) {
      e.printStackTrace();
    }
    if (loudness > 0) {
      System.out.println("Loaded class: " + name + " with " + c.getClassLoader());
    }
       
    return c;
  } 


  private void printPolicy(final Class c) {
    String classname = System.getProperty("org.cougaar.core.security.bootstrapper.policydebug");
    if (classname == null) {
      return;
    }
    else if (!classname.equals("all")) {
      // Only display information for a fully-qualified named class
      if (!classname.equals(c.getName())) {
	return;
      }
    }
    ProtectionDomain pd = (ProtectionDomain)
      AccessController.doPrivileged(new PrivilegedAction() {
	public Object run() {
	  ProtectionDomain p = c.getProtectionDomain();
	  return p;
	}
      });
    CodeSource cs = pd.getCodeSource();
    PermissionCollection pc = pd.getPermissions();
    Enumeration perm = pc.elements();
    System.out.println("Class: " + c + " - Code Source:" + cs + " - Permissions:");
    while (perm.hasMoreElements()) {
      System.out.println(perm.nextElement());
    }
  }
}

