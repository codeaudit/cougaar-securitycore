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

/** This exception is being thrown by the org.cougaar.core.security.authenticatedClassLoader *
  * if either the class itself or one of the classes that it is trying to instantiate is *
  * untrusted.
  * There maybe several reasons for considering a class untrusted --
  *     - it may be unsigned when signature is required;
  *     - none of the certificates that come with the jar file (where needed class resides) is trusted;
  *     - the jar file is not trusted, i.e. some of its classes/MANIFEST file/.SF file/ .DSA file 
  *        have been tempered with
  **/

public class AuthenticatedClassLoaderException extends Exception {
    public String classname;

    AuthenticatedClassLoaderException(String name) {
        super("Class named \"" + name + "\" has not been found among the trusted classes");
        classname = name;
    }

}
