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

import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarFile;

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

public class SecureBootstrapper
  extends BaseBootstrapper
{
  private SecurityLog securelog=null;

  private boolean lazySignatureVerification = true;

  private static Logger _logger = Logger.getInstance();

  /** Find the primary application entry point for the application class
   *  and call it.
   *  The default implementation will look for
   *  static void launch(String[]) and then 
   *  static void main(String[]).
   * This method contains all the reflection code for invoking the application.
   **/
  protected void launchMain(final ClassLoader cl, final String classname,
			    final String[] args) {
    final String node = getNodeName();
    try {
      if(_logger.isDebugEnabled()) {
        _logger.debug("Node being loaded: " + node);
      }
      SecureBootstrapper.super.launchMain(cl, classname, args);
    }
    catch (Exception e) {
      _logger.warn("Unable to start application:" + e);
    }
  }

  protected void createJarVerificationLog() {
    securelog = SecurityLogImpl.getInstance();
    securelog.createLogFile(getNodeName());
    if (_logger.isDebugEnabled()) {
      _logger.debug("Jar verification log created");
    }
  }

  public void setSecurityManager()
  {
    boolean useSecurityManager = 
      (Boolean.valueOf(System.getProperty("org.cougaar.core.security.useSecurityManager", "true"))).booleanValue();    
    if (useSecurityManager == true) {
      // Set Java Security Manager
      if(getNodeName() != null){
	System.setSecurityManager(new CougaarSecurityManager(getNodeName()));
      }
      else{
	_logger.debug("node name is null");
      }
    }
    if (_logger.isDebugEnabled()) {
      _logger.debug("Security Manager set");
    }
  }

  protected ClassLoader createClassLoader(List l) {
    ClassLoader cl = null;

    if (_logger.isDebugEnabled()) {
      _logger.debug("SecureBootstrapper.createClassLoader");
    }
    removeBootClasses(l);
    URL urls[] = (URL[]) l.toArray(new URL[l.size()]);

    boolean useAuthenticatedLoader =
      (Boolean.valueOf(System.getProperty("org.cougaar.core.security.useAuthenticatedLoader",
					  "true"))).booleanValue();

    if (useAuthenticatedLoader == true) {
      if (_logger.isDebugEnabled()) {
	_logger.debug("Using authenticated class loader");
      }
      URL[] trustedURLs = getTrustedArchives(urls);
      cl = new SecureClassLoader(trustedURLs);
    }
    else {
      if (_logger.isDebugEnabled()) {
	_logger.debug("Using legacy class loader");
      }
      cl = new BaseClassLoader(urls);
    }
    return cl;
  }
  /** verify each archive to be trusted */
  private URL[] getTrustedArchives(URL[] urls) {
    CertificateVerifier cv = CertificateVerifierImpl.getInstance();
    ArrayList trustedJars = new ArrayList();

    for (int i = 0 ; i < urls.length ; i++) {
      JarFile jf=null;
      try {
	// Delegate signature verification to the secure class loader
	// if lazy evaluation is set to true
	if (lazySignatureVerification == false) {
	  //create JarFile, set verification option to true
	  //will throw exception if cannot be verified
	  jf = new JarFile(urls[i].getPath(), true);

	  //do certificate verification, throw an exception
	  //and exclude from urls if not trusted
	  cv.verify(jf);
	}
	if (_logger.isDebugEnabled()) {
	  _logger.debug(urls[i].getPath() + " has been verified");
	}
	trustedJars.add(urls[i]);

      } catch (Exception e) {
	/* When the security services fail to be verified, we exit
	   because the security services are a critical component. */
	if (_logger.isDebugEnabled()) {
	  _logger.debug(urls[i]
			     + " could not be verified. " + e);
	}
	if (e instanceof GeneralSecurityException
	    || e instanceof SecurityException) {
	  continue;
	}
      }
    }
    URL trustedURLs[] =
      (URL[]) trustedJars.toArray(new URL[trustedJars.size()]);

    if(_logger.isDebugEnabled()) {
      printcodearchives(trustedURLs);
    }
    return trustedURLs;
  }

  private void printcodearchives(URL[] arch) {
    _logger.debug("trusted archives:");
    for(int i=0;i<arch.length;i++) {
	_logger.debug(arch[i].toString());
    }
  }

}
