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

package java.util.singleton;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class BaseSingleton
{
  private static final Logger _logger = Logger.getInstance();

  /**
   * Helper method to instantiate a "true" singleton.
   * The singleton is instantiated once per VM, even if there
   * are multiple ClassLoaders.
   * @param singletonClass - the class that will be instantiated as a singleton
   * @param interfaceClass - the interface implemented by the singleton
   * @param theInstance - a handle to the singleton
   */
  protected static Object getInstance(Class singletonClass,
				      Class interfaceClass,
				      Object theInstance) {
    ClassLoader myClassLoader = singletonClass.getClassLoader();
    if (theInstance==null) {
      // The root classloader is sun.misc.Launcher package.
      // If we are not in a sun package, we need to get hold of
      // the instance of ourself from the class in the root classloader.
      // getClassLoader() may return null for the bootstrap
      // ClassLoader, or it may return sun.misc.Launcher
      if (!(myClassLoader == null ||
	    myClassLoader.toString().startsWith("sun."))) {
	Object instance = null;
	try {
	  // So we find our parent classloader
	  ClassLoader parentClassLoader =
	    singletonClass.getClassLoader().getParent();
	  // And get the other version of our current class
	  Class otherClassInstance = parentClassLoader.loadClass
	    (singletonClass.getName());
	  // And call its getInstance method
	  // This gives the correct instance of ourself
	  Method getInstanceMethod = otherClassInstance.getDeclaredMethod
	    ("getInstance", new Class[] { });
	  Object otherInstance = getInstanceMethod.invoke
	    (null, new Object[] { } );
	  // But, we can't cast it to our own interface directly because
	  // classes loaded from different classloaders implement
	  // different versions of an interface.
	  // So instead, we use java.lang.reflect.Proxy to wrap it in an
	  // object that *does* support our interface, and the proxy will
	  // use reflection to pass through all calls
	  // to the object.
	  instance =
	    Proxy.newProxyInstance
	    (myClassLoader,
	     new Class[] {interfaceClass},
	     new PassThroughProxyHandler(otherInstance));

	} catch (Exception e) {
	  throw new RuntimeException("Unable to instantiate class: "
				     + singletonClass.getName(), e);
	}
	/* Do a sanity check to verify that the proxy actually
	 * implements the desired interface.
	 * Normally, this would be done by doing the following:
	 if (instance.getClass().isInstance(interfaceClass)) {
	 theInstance = instance;
	 }
	 This works on Linux but not Windows. I would think the Windows
	 implementation is correct since the class has been loaded
	 by a different class loader.
	 The code below is not really necessary but it helps for
	 debugging.
	*/
	Class[] intf = instance.getClass().getInterfaces();
	boolean isImplemented = false;
	if (intf != null) {
	  for (int i = 0 ; i < intf.length ; i++) {
	    if (interfaceClass.getName().equals(intf[i].getName())) {
	      isImplemented = true;
	      break;
	    }
	  }
	}
	if (isImplemented) {
	  theInstance = instance;
	}
	else {
	  String s = "Interfaces implemented by " +
	    instance.getClass().getName() + ":";
	  if (intf != null) {
	    for (int i = 0 ; i < intf.length ; i++) {
	      s = s + " " + intf[i].getName();
	    }
	  }
	  if (_logger.isWarnEnabled()) {
	    _logger.warn(s);
	  }
	  // Error. The instance should implement interfaceClass
	  throw new RuntimeException("Error: "
				     + instance.getClass().getName()
				     + " does not implement "
				     + interfaceClass.getName() + " - " + s);
	}
      } else {
	// We're in the root classloader, so the instance we have here
	// is the correct one
	try {
	  theInstance = singletonClass.newInstance();
	}
	catch (Exception e) {
	  String s = "Unable to instantiate class: "
	    + singletonClass.getName();
	  if (_logger.isWarnEnabled()) {
	    _logger.warn(s);
	  }
	  throw new RuntimeException(s, e);
	}
      }
    }
    return theInstance;
  }
}
