/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.Hashtable;
import java.util.jar.JarFile;

public class SecureClassLoader  extends BaseClassLoader{

  private static final Logger _logger = Logger.getInstance();
  private CertificateVerifier certificateVerifier;
  private Hashtable verifiedUrls;
  private boolean lazySignatureVerification;
  
  /** Log file to store Jar verification errors */
  private static SecurityLog _securelog;

  public SecureClassLoader(URL urls[])
    {
      super(urls);
      lazySignatureVerification = true;
      // Instantiate certificate verifier is lazy signature verification is performed
      certificateVerifier = CertificateVerifierImpl.getInstance();
      verifiedUrls = new Hashtable();
      _securelog = SecurityLogImpl.getInstance();
    }

  /** calls findClass(String name) throws ClassNotFoundException
   *  of URLClassLoader.java
   */
  protected synchronized Class findClass(String classname)
    throws ClassNotFoundException, SecurityException {
    Class c = null;
    // String sep =  System.getProperty("file.separator", "/");
    String name=classname;
    final String path = name.replace('.','/' ).concat(".class");
    URL  urlForClass=null;
    URL tempurlForClass=null;
    tempurlForClass=  (URL) AccessController.doPrivileged(new PrivilegedAction() {
        public Object run(){
          URL url=(URL)findResource(path);
          return url;
        }
      });
    
    if(tempurlForClass!= null) {
      
      String tempurl=tempurlForClass.getPath();
      String newurl=tempurl.substring(0,tempurl.indexOf('!'));
      try {
        urlForClass=new URL(newurl);
      }
      catch (Exception exp1){
        throw new ClassNotFoundException("Cannot Create URL  :",exp1);
      }
      if (lazySignatureVerification) {
        if (urlForClass== null) {
          System.out.println("Unknown URL for " + c.getName());
        }
        else {
          Boolean isVerified = (Boolean) verifiedUrls.get(urlForClass);
          if (isVerified == null) {
            // The JAR file has not been verified yet. Verify it.
            //System.out.println("Checking " + urlc.getPath());
            try {
              //create JarFile, set verification option to true
              //will throw exception if cannot be verified
              JarFile jf = new JarFile(urlForClass.getPath(), true);
              
              //do certificate verification, throw an exception
              //and exclude from urls if not trusted
              certificateVerifier.verify(jf);
	      jf.close();
              verifiedUrls.put(urlForClass, Boolean.TRUE);
            }
            catch (Exception e) {
              //e.printStackTrace();
              verifiedUrls.put(urlForClass, Boolean.FALSE);
              // _securelog.logJarVerificationError(urlForClass, e);
              c = null;
              throw new ClassNotFoundException("Class cannot be Trusted ",e);
            }
          }
          else if (isVerified == Boolean.FALSE) {
            // The signature has already been checked and it is not correct
            c = null;
            throw new ClassNotFoundException("Class cannot be Trusted ");
          }
        }
      }
    }
    try {
      c = super.findClass(classname);             
    } catch (ClassNotFoundException e) {
      // catch exception silently due to the fact that multiple
      // property group classes are currently specified without
      // their fully qualified path in the .ini files
      // and are later looked up in multiple packages until found
    }
    catch (SecurityException securityexp){
      if(urlForClass!=null) {
        verifiedUrls.put(urlForClass, Boolean.FALSE);
        //_securelog.logJarVerificationError(urlForClass,securityexp);
      }
      _securelog.logJarVerificationError(urlForClass,securityexp);
      StringBuffer message=new StringBuffer("Jar file has been tampered : ");
      if(urlForClass!=null){
        message.append(urlForClass.toString());
      }
      SecurityException sexp= new SecurityException(message.toString()) ;
      sexp.setStackTrace(securityexp.getStackTrace());
      throw sexp;
    }
    if (_logger.isDebugEnabled()) {
      printPolicy(c);
    }
    return c;
  }
  
}



