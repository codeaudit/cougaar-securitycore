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

import java.util.*;
import java.security.*;
import java.net.*;

/** Use slightly different rules for class loading:
 * Prefer classes loaded via this loader rather than 
 * the parent.
 **/

class BootstrapClassLoader extends URLClassLoader {
  private static int loudness = 0;
  private static final List exclusions = new ArrayList();
  static {
    String sp = System.getProperty("org.cougaar.core.society.bootstrapper.loud");
    if ("true".equals(sp)) {
      loudness = 1;
    } else if ("shout".equals(sp)) {
      loudness = 2;
    } else if ("false".equals(sp)) {
      loudness = 0;
    }

    exclusions.add("java.");
    exclusions.add("javax.");
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
  }
 
  public BootstrapClassLoader(URL urls[]) {
    super(urls);
    if (loudness>0) {
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
  // From the Java 2 SDK, v1.2, subclasses of ClassLoader are encouraged
  // to override findClass(String), rather than loadClass().
  protected Class findClass(String name)
    throws ClassNotFoundException
  {
    try {
      final Class c = super.findClass(name);
      if (loudness>1) {
	// Classes loaded by the bootstrapper shouldn't have
	// the privilege to get the protection domain (this should be
	// set in the Java policy file).
	// Therefore, we need to execute the following piece of code
	// in a doPrivileged() call.
	AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
	      // privileged code goes here, for example:
	      java.security.ProtectionDomain pd = c.getProtectionDomain();
	      if (pd != null) {
		java.security.CodeSource cs = pd.getCodeSource();
		if (cs != null) {
		  System.err.println("BCL: "+c+" loaded from "+cs.getLocation());
		}
	      }
	      return null; // nothing to return
            }
	  });
      }
      return c;
    }
    catch (Exception e) {
      throw new ClassNotFoundException(name);
    }
  }
  
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

}
