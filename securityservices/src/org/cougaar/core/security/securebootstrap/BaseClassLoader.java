/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.securebootstrap;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.PermissionCollection;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class BaseClassLoader
extends XURLClassLoader
{
  private static final Logger _logger = Logger.getInstance();
  private static final String PROP_EXCLUSIONS =
  "org.cougaar.bootstrapper.exclusions";
  protected static List exclusions = new ArrayList();

  static {
    /* All classes in the excluded list will be loaded
       by system class loader. 
    */
    exclusions.add("java.");  // avoids javaiopatch.jar
    // let base do it instead
    exclusions.add("org.cougaar.core.security.crlextension");
    exclusions.add("javax.xml");

    // BUG Cougaar 3086:
    // The SAXParserFactory.newInstance() has a local variable of
    // type SAXParserFactory which has been loaded by the
    // primordial class loader. The methods sets this variable
    // to an instance of a SAXParserFactory that must be loaded
    // by the same class loader.
    //exclusions.add("javax.xml.");
    //exclusions.add("org.xml.");
    //exclusions.add("org.w3c.");

    //exclusions.add("com.sun.");
    //exclusions.add("sun.");
    //exclusions.add("net.jini.");
    String s = System.getProperty(PROP_EXCLUSIONS);
    if (s != null) {
      String extras[] = s.split(":");
      for (int i = 0; i<extras.length; i++) {
        exclusions.add(extras[i]);
      }
    }
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

  public BaseClassLoader(URL urls[]) {
    super(urls);
    if (_logger.isDebugEnabled()) {
      _logger.debug("Bootstrapper URLs: ");
      for (int i=0; i<urls.length; i++) {
	_logger.debug("\t"+urls[i] + " - Protocol:" + urls[i].getProtocol());
      }
    }
    /* Do not use caches by default.
    * sun.net.www.protocol.jar.JarFileFactory maintains a static cache of
    * all JarFiles. So all JarFiles would be strongly referenced by the
    * Java runtime environment. The cache grows and can never shrink.
    * The only way to prevent Jar files to get into the cache is to invoke
    * URLConnection.setDefaultUseCaches(false).
    * The interface is really weird. It should be a static method, but it
    * is not.
    * Commented out for now. The VM core classes have another reference to
    * the JarFiles anyway, so executing the code below wouldn't help anyway.
    */
    for (int i = 0 ; i < urls.length ; i++) {
      try {
        URLConnection myUrl = urls[i].openConnection();
        // setDefaultUseCaches is in fact a static field, but the method
        // is not static. We need to find at least one connection that
        // succeeds.
        myUrl.setDefaultUseCaches(false);
        System.out.println("setDefaultUseCaches set to false");
        break;
      }
      catch (IOException e) {}
    }
  }
  /*
   */
  protected synchronized Class loadClass(final String name, boolean resolve)
    throws ClassNotFoundException {
    // First, check if the class has already been loaded
    Class c = findLoadedClass(name);

    // Then delegate to parent class loader
    if (c == null) {
      ClassLoader parent = getParent();
      if (parent == null) parent = getSystemClassLoader();
      try {
        c = parent.loadClass(name);
      }
      catch (ClassNotFoundException e) {}
    }

    // Finally, use our search path to find classes.
    if (c == null) {
      // make sure not to use this classloader to load
      // java.*.  We patch java.io. to support persistence, so it
      // may be in our jar files, yet those classes must absolutely
      // be loaded by the same loader as the rest of core java.
      //if (!excludedP(name)) {
	try {
	  c = findClass(name);
	  checkPackageAccess(name);
	}
	catch (ClassNotFoundException e) {
	  _logger.warn("Class not found  Exception:" + e);
          throw e;
       
	  // If still not found, then call findClass in order
	  // to find the class.
	}
      //}
    }
    
    if (_logger.isDebugEnabled()) {
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
		  _logger.debug("BCL: "+c1
				+ " loaded from "+cs.getLocation()
				+ " with "
				+ c1.getClassLoader().toString());
		}
	      }
              // The return value is not used.
              return null;
	    }
	  });
      }
      else {
	_logger.info("Unable to find class: " + name);
      }
    }
    if (c == null) {
      throw new ClassNotFoundException("Unable to find " + name);
    }
    if (resolve) {
      resolveClass(c);
    }
    return c;
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
    _logger.debug("Class: " + c + " - Code Source:"
		  + cs + " - Permissions:");
    while (perm.hasMoreElements()) {
      _logger.debug(perm.nextElement().toString());
    }
  }

}




