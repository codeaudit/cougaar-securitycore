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

package org.cougaar.core.security.securebootstrap;



import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.Collection;
import java.util.Iterator;
import java.security.*;
import org.cougaar.core.security.bootstrap.*;

public class SecureCougaarClassLoader extends CougaarClassLoader {
  private SecurityLog log=null;
  private HashMap unsecurejars;
  public SecureCougaarClassLoader(URL urls[], HashMap unsecure,SecurityLog alog)
  {
    super(urls);
    log=alog;
    unsecurejars=unsecure;
    Collection c=unsecurejars.values();
    Iterator i=c.iterator();
    URL url=null;
    for(; i.hasNext();)
      {
	url=(URL)i.next();
	System.out.println("Unsecure jar is :: "+ url.toString());
      }
  }
  protected void checkSecurityException(SecurityException e, String name)
  {
    log.logJarVerificationError(e);
    if (name.startsWith("org.cougaar.core.security")
	|| name.startsWith("org.cougaar.core.security")) {
      System.out.println("Cannot continue without security services:" + e);
      System.exit(0);
    }
  }

  /** calls findClass(String name) throws ClassNotFoundException of URLClassLoader.java
   */
  protected synchronized  Class findClass(String classname) throws ClassNotFoundException {
    Class c = null;
    try {
      c = super.findClass(classname);             
    } catch (ClassNotFoundException e) {
      //catch exception silently due to the fact that multiple property group classes
      //are currently specified without their fully qualified path in the .ini files
      //and are later looked up in multiple packages until found
    }
    
    if (c != null) {
      // Classes loaded by the bootstrapper shouldn't have
      // the privilege to get the protection domain (this should be
      // set in the Java policy file).
      // Therefore, we need to execute the following piece of code
      // in a doPrivileged() call.
     
      final Class c1 = c;
      URL urlc=(URL)
	AccessController.doPrivileged(new PrivilegedAction() {
	    public Object run() {
	      ProtectionDomain p = c1.getProtectionDomain();
	      if (p != null) {
		java.security.CodeSource cs = p.getCodeSource();
		if (cs != null) {
		  return cs.getLocation();
		}
	      }
	      return null;
	    }
	  });
      synchronized(unsecurejars)
	{
	  if(unsecurejars.containsKey(urlc.toString())) {
	    if(BaseBootstrapper.loudness>1)
	      System.out.println("Gotrequest for  class from unsecure jar list  "+ c.getName() + "location :  "+ urlc.toString()); 
	    // throw new  ClassNotFoundException(c.getName());  
	    return null;
	  }
	} 
    }
    
    if (BaseBootstrapper.loudness > 0) {
      printPolicy(c);
    }
    return c;
  }
  
}



