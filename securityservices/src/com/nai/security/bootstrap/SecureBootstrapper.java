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

import java.io.*;
import java.net.*;
import java.text.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.zip.*;
import java.util.jar.*;
import java.security.*;
import java.security.cert.*;

import org.cougaar.core.security.bootstrap.*;

/**
 * A bootstrapping launcher, in particular, for a node.
 * <p>
 * Figures out right classpath, creates a new classloader and
 * then invokes the usual static main method on the specified class
 * (using the new classloader).
 * <p>
 * Main job is to search for jar files, building up a collection
 * of paths to give to a special NodeClassLoader so that we don't
 * have to maintain many different script files.
 * <p>
 * <pre>
 * The following locations are examined, in order:
 *  -Dorg.cougaar.class.path=...	(like a classpath)
 *  $COUGAAR_INSTALL_PATH/lib/*.{jar,zip,plugin}
 *  $COUGAAR_INSTALL_PATH/plugins/*.{jar,zip,plugin}
 *  -Dorg.cougaar.system.path=whatever/*.{jar,zip,plugin}
 *  $COUGAAR_INSTALL_PATH/sys/*.{jar,zip,plugin}
 * </pre>
 * <p>
 * As an added bonus, Bootstrapper may be run as an application
 * which takes the fully-qualified class name of the class to run
 * as the first argument.  All other arguments are passed
 * along as a String array as the single argument to the class.
 * The class must provide a public static launch(String[]) or
 * main(String[]) method (searched for in that order).
 *
 * The Boostrapper's classloader will not load any classes which
 * start with "java.". This
 * list may be extended by supplying a -Dorg.cougaar.core.society.bootstrapper.exclusions=foo.:bar.
 * System property.  The value of the property should be a list of
 * package prefixes separated by colon (":") characters.
 * <p>
 * A common problem is the attempt to use "patch" jar files to repair a few
 * classes of some much larger archive.  There are two problems with this
 * use pattern: (1) the order that Bootstrapper will find jar files in a
 * directory is undefined - there is no guarantee that the patch will take
 * precedence over the original.  Also, (2) classloaders will refuse to
 * load classes of a given package from multiple jar files - if the patch jar
 * does not contain the whole package, the classloader will likely be
 * unable to load the rest of the classes.  Both problems tend to
 * crop up when you can least afford this confusion.
 * <p>
 * The System property <em>org.cougaar.core.society.bootstrapper.loud</em>
 * controls debugging output of the bootstrapping classloader.  When set to
 * "true" will output the list of jar/zip files used to load classes (in order).
 * When set to "shout" will additionally print the location of the jar/zip file
 * used to load each and every class.
 **/
public class SecureBootstrapper extends BaseBootstrapper
{
  SecurityLog securelog=null;
  private HashMap untrustedjars;
  public static void main(String[] args) {
    String[] launchArgs = new String[args.length - 1];
    System.arraycopy(args, 1, launchArgs, 0, launchArgs.length);
    SecureBootstrapper bootstrapper=new SecureBootstrapper();
    bootstrapper.launch(args[0], launchArgs);
  }

  protected void createJarVerificationLog(String nodeName) {
    securelog=new SecurityLog();
    securelog.createLogFile(nodeName);

 
  }
  public SecureBootstrapper()
  {
    untrustedjars=new HashMap();
  }

  /** verify each archive to be trusted */
  protected URL[] getTrustedArchives(CodeArchive[] codeArchives)
    throws IOException
  {
    for (int i=0; i<codeArchives.length; i++) {
      if (codeArchives[i].getSignatureRequired() == false) {
	if (loudness > 0) {
	  System.out.println(codeArchives[i].getURL() + " signature will not be checked");
	}
	continue;
      }
      JarFile jf=null;
      try {

	CertificateVerifier cv = new CertificateVerifier();

	//create JarFile, set verification option to true
	//will throw exception if cannot be verified
	jf = new JarFile(codeArchives[i].getURL().getPath(), true);

	//do certificate verification, throw an exception
	//and exclude from urls if not trusted
	cv.verify(jf);
	//if (loudness > 0)
	//System.out.println(codeArchives[i].getURL() + " has been verified");

      } catch (Exception e) {
	/* When the security services fail to be verified, we exit
	   because the security services are a critical component. */
	Enumeration en = jf.entries();
	while (en.hasMoreElements()) {
	  ZipEntry ze = (ZipEntry) en.nextElement();
	  if (ze.getName().startsWith("com/nai/security")
	      || ze.getName().startsWith("com\\nai\\security")
	      || ze.getName().startsWith("org/cougaar/core/security")
	      || ze.getName().startsWith("org\\cougaar\\core\\security")) {
	    System.out.println("Cannot continue without security services:"
			       + e);
	    securelog.logJarVerificationError(e);
	    System.exit(0);
	  }
	}
	if (loudness > 0)
	  System.out.println(codeArchives[i].getURL()
			     + " could not be verified. " + e);
	if (e instanceof GeneralSecurityException
	    || e instanceof SecurityException) {
	  e.printStackTrace();
	  codeArchives = excludeFromURLs(codeArchives, i);
	  //urls[i] one more time -- it now contains a different URL
	  i--;
	  //report to the log
	  securelog.logJarVerificationError(e);
	  continue;
	}
      }

    }
    //printcodearchives(codeArchives);
    return getURLs(codeArchives);
  }
  protected void printcodearchives(CodeArchive[] arch)
  {
    if(BaseBootstrapper.loudness>0) {
      CodeArchive carch=null;
      System.out.println("trusted archive is :::");
      for(int i=0;i<arch.length;i++) {
	System.out.println(arch[i].getURL().toString());
      }
    }
  }

  /** helper method to remove urls that are not trusted */
  protected CodeArchive[] excludeFromURLs(CodeArchive[] codeArchives, int index) {
    CodeArchive[] newCodeArchives = new CodeArchive[codeArchives.length - 1];
    System.arraycopy(codeArchives, 0, newCodeArchives, 0, index);
    untrustedjars.put(codeArchives[index].getURL().toString(),codeArchives[index].getURL());
    System.arraycopy(codeArchives, index + 1, newCodeArchives, index, newCodeArchives.length - index);
    return newCodeArchives;
  }
  public HashMap getuntrustedpath()
  {
    return untrustedjars;
    
  }

  protected void accumulateJars(List l, File f)
  {
    accumulateJars(l,f,true);
  }

  protected  void accumulateClasspath(List l, String path)
  {
    accumulateClasspath(l, path,true);
  }
  
  protected ArrayList accumulateJarsandClasspath(String base)
  {
    ArrayList l=super.accumulateJarsandClasspath(base);
    accumulateClasspath(l, System.getProperty("java.class.path"));
    if(BaseBootstrapper.loudness>1)
      {
	System.out.println("classpath from secure bootstrapper::  "+ System.getProperty("java.class.path"));
	printlist(l);
      }
    return l;
    
  }

  public void setSecurityManager(String nodeName)
  {
    boolean useSecurityManager = 
      (Boolean.valueOf(System.getProperty("org.cougaar.core.security.useSecurityManager", "true"))).booleanValue();    
    if (useSecurityManager == true) {
      // Set Java Security Manager
      if(nodeName!=null){
	System.setSecurityManager(new CougaarSecurityManager(nodeName));
      }
      else{
	System.out.println("node name is null");
      }
    }
  }
  public void setClassLoader( CodeArchive[] codeArchives)
  {
    try {
      boolean useAuthenticatedLoader =
	(Boolean.valueOf(System.getProperty("org.cougaar.core.security.useAuthenticatedLoader", "true"))).booleanValue();
      if (useAuthenticatedLoader == true) {
	if (loudness > 0) {
	  System.out.println("Using authenticated class loader");
	}
	baseclassloader = new SecureCougaarClassLoader(getTrustedArchives(codeArchives),getuntrustedpath(), securelog);
      }
      else {
	if (loudness > 0) {
	  System.out.println("Using legacy class loader");
	}
	baseclassloader = new CougaarClassLoader(getURLs(codeArchives));
	 
      }
    }
    catch (Exception e) {
      System.err.println("Failed to launch startclassloader :  ");
      e.printStackTrace();
    }
  }
}









