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
import java.util.Hashtable;
import java.util.jar.JarFile;
import java.security.*;

public class SecureClassLoader
  extends BaseClassLoader
{
  private SecurityLog securelog=null;
  private CertificateVerifier certificateVerifier;
  private Hashtable verifiedUrls;
  private boolean lazySignatureVerification;

  public SecureClassLoader(URL urls[], SecurityLog log, int loudness)
  {
    super(urls, loudness);
    securelog = log;

    lazySignatureVerification = true;
    // Instantiate certificate verifier is lazy signature verification is performed
    certificateVerifier = new CertificateVerifier();
    verifiedUrls = new Hashtable();
  }

  protected void checkSecurityException(SecurityException e, String name)
  {
    securelog.logJarVerificationError(e);
  }

  /** calls findClass(String name) throws ClassNotFoundException
   *  of URLClassLoader.java
   */
  protected synchronized Class findClass(String classname)
    throws ClassNotFoundException {
    Class c = null;
    try {
      c = super.findClass(classname);             
    } catch (ClassNotFoundException e) {
      // catch exception silently due to the fact that multiple
      // property group classes are currently specified without
      // their fully qualified path in the .ini files
      // and are later looked up in multiple packages until found
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

      /* Check the jar file signature */
      if (lazySignatureVerification) {
	if (urlc == null) {
	  //System.out.println("Unknown URL for " + c.getName());
	}
	else {
	  Boolean isVerified = (Boolean) verifiedUrls.get(urlc);
	  if (isVerified == null) {
	    // The JAR file has not been verified yet. Verify it.
	    //System.out.println("Checking " + urlc.getPath());
	    try {
	      //create JarFile, set verification option to true
	      //will throw exception if cannot be verified
	      JarFile jf = new JarFile(urlc.getPath(), true);
	      
	      //do certificate verification, throw an exception
	      //and exclude from urls if not trusted
	      certificateVerifier.verify(jf);
	      verifiedUrls.put(urlc, Boolean.TRUE);
	      //System.out.println(urlc.getPath() + " has been verified");
	    }
	    catch (Exception e) {
	      //System.out.println(urlc.getPath() + " does not have valid signature");
	      securelog.logJarVerificationError(e);
	      verifiedUrls.put(urlc, Boolean.FALSE);
	      c = null;
	    }
	  }
	  else if (isVerified == Boolean.FALSE) {
	    // The signature has already been checked and it is not correct
	    c = null;
	  }
	}
      }
    }
    //if (c == null) {
      //System.out.println("unknown class: " + classname);
    //}
    if (loudness > 0) {
      printPolicy(c);
    }
    return c;
  }
  
}



