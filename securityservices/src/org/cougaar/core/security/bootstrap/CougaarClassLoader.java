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

package org.cougaar.core.security.bootstrap;

import java.lang.*;
import java.util.jar.*;
import java.util.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;

//import org.cougaar.core.security.bootstrap.*;

public class CougaarClassLoader extends XURLClassLoader {
  protected static List exclusions = new ArrayList();
  static {
    /* All classes in the excluded list will be loaded
       by system class loader. 
    */
    exclusions.add("java.");  // avoids javaiopatch.jar
    // let base do it instead
    //exclusions.add("javax.");
    //exclusions.add("com.sun.");
    //exclusions.add("sun.");
    //exclusions.add("net.jini.");
    String s = System.getProperty("org.cougaar.bootstrapper.exclusions");
    if (s != null) {
      List extras = explode(s, ':');
      if (extras != null) {
	exclusions.addAll(extras);
      }
    }
  }
  static  final List explode(String s, char sep) {
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

  private boolean excludedP(String classname) {
    int l = exclusions.size();
    for (int i = 0; i<l; i++) {
      String s = (String)exclusions.get(i);
      if (classname.startsWith(s))
	return true;
    }
    return false;
  }

  public CougaarClassLoader(URL urls[]) {
    super(urls);
    if (BaseBootstrapper.loudness>0) {
      synchronized(System.err) {
	System.err.println();
	System.err.println("Bootstrapper URLs: ");
	for (int i=0; i<urls.length; i++) {
	  System.err.println("\t"+urls[i]);
	}
	System.err.println();
      }
    }
  }
  /*
   */
  protected synchronized Class loadClass(String name, boolean resolve)
    throws ClassNotFoundException
  {
    // First, check if the class has already been loaded
    Class c = findLoadedClass(name);
    if (c == null) {
      // make sure not to use this classloader to load
      // java.*.  We patch java.io. to support persistence, so it
      // may be in our jar files, yet those classes must absolutely
      // be loaded by the same loader as the rest of core java.
      if (!excludedP(name)) {
	try {
	  c = findClass(name);
	  checkPackageAccess(name);
	  }
	catch (ClassNotFoundException e) {
	  // if(BaseBootstrapper.loudness>0) {
	   System.err.println("Class not found  Exception:");
	  // e.printStackTrace();
	    // } 
	  // If still not found, then call findClass in order
	  // to find the class.
	}
	catch (SecurityException sexp) {
	  if(BaseBootstrapper.loudness>0) {
	    System.err.println("Security Exception:");
	    sexp.printStackTrace();
	  }
	  checkSecurityException(sexp,name);
	}
	
      }
    }
      if (c == null) {
	ClassLoader parent = getParent();
	if (parent == null) parent = getSystemClassLoader();
	c = parent.loadClass(name);
      }
      if (BaseBootstrapper.loudness>1) {
	if (c != null) {
	  // Classes loaded by the bootstrapper shouldn't have
	  // the privilege to get the protection domain (this should be
	  // set in the Java policy file).
	  // Therefore, we need to execute the following piece of code
	  // in a doPrivileged() call.
	  final Class c1 = c;
	  AccessController.doPrivileged(new PrivilegedAction() {
	      public Object run() {
		ProtectionDomain p = c1.getProtectionDomain();
		if (p != null) {
		  java.security.CodeSource cs = p.getCodeSource();
		  if (cs != null) {
		    System.err.println("BCL: "+c1
				       + " loaded from "+cs.getLocation()
				       + " with "
				       + c1.getClassLoader().toString());
		  }
		}
		return null;
	      }
	    });
	}
	else {
	  System.out.println("Unable to find class: " + name);
	}
      }
    if (resolve) {
      resolveClass(c);
    }
    return c;
  }

  protected void checkSecurityException(Exception e, String name)
  {
  }

  protected boolean checkPackageAccess(String classpath)
    throws SecurityException
  {
    SecurityManager sm = System.getSecurityManager();
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

  public  void printPolicy(final Class c) {
    String classname = System.getProperty("org.cougaar.core.security.bootstrapper.policydebug");
    if (classname == null || c == null) {
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




