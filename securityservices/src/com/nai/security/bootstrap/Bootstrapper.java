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
import java.lang.reflect.*;
import java.net.*;
import java.util.*;
import java.util.zip.*;
import java.util.jar.*;
import java.security.cert.*;
import java.security.*;
import java.text.*;

import com.nai.security.bootstrap.*;

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
 *  $CLASSPATH
 *  $ALP_INSTALL_PATH/lib/*.{jar,zip,plugin}
 *  $ALP_INSTALL_PATH/plugins/*.{jar,zip,plugin}
 *  -Dalp.system.path=whatever/*.{jar,zip,plugin}
 *  $ALP_INSTALL_PATH/sys/*.{jar,zip,plugin} 
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
 * start with "java.", "javax.", "sun.", "com.sun." or "net.jini.".  This 
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
public class Bootstrapper
{
  private static int loudness = 0;
  static {
    String s = System.getProperty("org.cougaar.core.society.bootstrapper.loud");
    if ("true".equals(s)) {
      loudness = 1;
    } else if ("shout".equals(s)) {
      loudness = 2;
    } else if ("false".equals(s)) {
      loudness = 0;
    }
  }

  private static boolean isBootstrapped = false;


  /**
   * Node entry point.
   * If org.cougaar.useBootstrapper is true, will search for installed jar files
   * in order to load all classes.  Otherwise, will rely solely on classpath.
   *
   **/

  public static void main(String[] args) {
    String[] launchArgs = new String[args.length - 1];

    boolean useSecurityManager = 
      (Boolean.valueOf(System.getProperty("org.cougaar.core.security.useSecurityManager", "true"))).booleanValue();    
    if (useSecurityManager == true) {
      // Set Java Security Manager
      String nodeName = null;
      if (args.length > 2) {
	nodeName = args[2];
      }
      System.setSecurityManager(new CougaarSecurityManager(nodeName));
    }

    // Launch application
    System.arraycopy(args, 1, launchArgs, 0, launchArgs.length);
    launch(args[0], launchArgs);
  }

  /**
   * Reads the properties from specified url
   **/
  public static void readProperties(String propertiesURL){
    if (propertiesURL != null) {
      Properties props = System.getProperties();
      try {    // open url, load into props
	URL url = new URL(propertiesURL);
	InputStream stream = url.openStream();
	props.load(stream);
	stream.close();
      } catch (MalformedURLException me) {
	System.err.println(me);
      } catch (IOException ioe) {
	System.err.println(ioe);
      }
    }
  }
  
  /**
   * Search the likely spots for jar files and classpaths,
   * create a new classloader, and then invoke the named class
   * using the new classloader.
   * 
   * We will attempt first to invoke classname.launch(String[]) and
   * then classname.main(String []).
   **/
  public static void launch(String classname, String[] args){
    if (isBootstrapped) {
      throw new IllegalArgumentException("Circular Bootstrap!");
    }
    isBootstrapped = true;

    readProperties(System.getProperty("org.cougaar.properties.url"));

    ArrayList l = new ArrayList();
    String base = System.getProperty("org.cougaar.install.path");

    boolean useAuthenticatedLoader =
      (Boolean.valueOf(System.getProperty("org.cougaar.core.security.useAuthenticatedLoader", "true"))).booleanValue();

    accumulateClasspath(l, System.getProperty("org.cougaar.class.path"));
    accumulateClasspath(l, System.getProperty("java.class.path"));
    accumulateJars(l, new File(base,"lib"));
    accumulateJars(l, new File(base,"plugins"));

    // Classes in the boot class path are not signed so don't
    // verify their signature (although this could be done).
    // Note that we rely on the boot class path to contain
    // valid class files. If these files have been tampered, there is
    // not much we can guarantee.
    //accumulateClasspath(l, System.getProperty("sun.boot.class.path"), false);

    String sysp = System.getProperty("org.cougaar.system.path");
    if (sysp!=null) {
      accumulateJars(l, new File(sysp));
    }

    accumulateJars(l,new File(base,"sys"));
    CodeArchive[] codeArchives = (CodeArchive[]) l.toArray(new CodeArchive[l.size()]);

    try {
      // The following line would use a different type of a classloader
      // (secure class loader)
      // Use new AuthenticatedClassLoader to verify Jar file signatures
      URLClassLoader cl = null;
      if (useAuthenticatedLoader == true) {
	if (loudness > 0) {
	  System.out.println("Using authenticated class loader");
	}
	String nodeName = null;
	if (args.length > 1) {
	  nodeName = args[1];
	}
        createJarVerificationLog(nodeName);
        cl = new AuthenticatedClassLoader(getTrustedArchives(codeArchives));
      }
      else {
	if (loudness > 0) {
	  System.out.println("Using legacy class loader");
	}
	cl = new BootstrapClassLoader(getURLs(codeArchives));
      }
      // The following line is not necessary in the current implementation (?)
      Thread.currentThread().setContextClassLoader(cl);

      Class realnode = cl.loadClass(classname);

      Class argl[] = new Class[1];
      argl[0] = String[].class;
      Method main;
      try {
        // try "launch" first
        main = realnode.getMethod("launch", argl);
      } catch (NoSuchMethodException nsm) {
        // if this one errors, we just let the exception throw up.
        main = realnode.getMethod("main", argl);
      }

      Object[] argv = new Object[1];
      argv[0] = args;
      main.invoke(null,argv);
    } catch (Exception e) {
      System.err.println("Failed to launch "+classname+": ");
      e.printStackTrace();
    }
  }

  protected static PrintStream log = null;

  protected static void createJarVerificationLog(String nodeName) {

    // Get name of the log file
    String sep =  System.getProperty("file.separator", "/");
    // Since multiple nodes may run on the same machine, we need
    // to make sure two nodes will not write to the same log file.
    // Also, log files should not be overwritten each time a
    // node is started again (for forensic purposes).
    Calendar rightNow = Calendar.getInstance();
    String curTime = rightNow.get(Calendar.YEAR) + "-" +
      rightNow.get(Calendar.MONTH) + "-" +
      rightNow.get(Calendar.DAY_OF_MONTH) + "-" +
      rightNow.get(Calendar.HOUR_OF_DAY) + "-" +
      rightNow.get(Calendar.MINUTE);

    String defaultLogName =
      System.getProperty("org.cougaar.install.path", "") +
      sep + "log" + sep + "bootstrap" + sep + "JarVerification_"
      + nodeName + "_" + curTime + ".log";
    String logname =
      System.getProperty("org.cougaar.core.security.bootstrap.JarVerificationLogFile",
			 defaultLogName);

    if (loudness > 0) {
      System.out.println("Creating Jar Verification Log " + logname);
    }

    try {
      log = new PrintStream(new FileOutputStream(logname));
      log.print("<logtime>"+DateFormat.getDateInstance().format(new Date())+"</logtime>\n");
      log.print("<nodeName>"+nodeName+"</nodeName>\n");
    }
    catch (IOException e) {
      System.err.println("Jar verification log file not opened properly\n" + e.toString());
    }
  }


  /** Logs exceptions of type java.security.GeneralSecurityException and java.lang.SecurityException */
  private static void logJarVerificationError (Exception e) {
    // Could be used to report jar file verification exceptions to a Monitoring & Response
    // PlugIn.
    String curTime = DateFormat.getDateInstance().format(new Date());
    log.print("<securityEvent><time>" + curTime + "</time>");
    log.print(e.getMessage());    
    log.print("\n<stack>\n");
    e.printStackTrace(log);
    log.print("</stack></securityEvent>\n");
  }



  /** verify each archive to be trusted */
  protected static URL[] getTrustedArchives(CodeArchive[] codeArchives) throws IOException{
    for (int i=0; i<codeArchives.length; i++) {
      if (codeArchives[i].getSignatureRequired() == false) {
	if (loudness > 0) {
	  System.out.println(codeArchives[i].getURL() + " signature will not be checked");
	}	  
	continue;
      }
      try {
          
	CertificateVerifier cv = new CertificateVerifier();

	//create JarFile, set verification option to true
	//will throw exception if cannot be verified
	JarFile jf = new JarFile(codeArchives[i].getURL().getPath(), true);

	//do certificate verification, throw an exception 
	//and exclude from urls if not trusted
	cv.verify(jf);
	if (loudness > 0)
	  System.out.println(codeArchives[i].getURL() + " has been verified");

      }catch (Exception e) {
	if (loudness > 0)
	  System.out.println(codeArchives[i].getURL() + " could not be verified");

	if (e instanceof GeneralSecurityException || e instanceof SecurityException) {
	  e.printStackTrace();
	  codeArchives = excludeFromURLs(codeArchives, i);
	  //urls[i] one more time -- it now contains a different URL
	  i++;
	  //report to the log
	  logJarVerificationError(e);
	  continue;
	}
      }

    }
                           
    return getURLs(codeArchives);
  }

  static URL[] getURLs(CodeArchive[] codeArchives) {
    URL[] urls = new URL[codeArchives.length];
    for (int i=0; i<codeArchives.length; i++) {
      // Also create an array of URLs
      urls[i] = codeArchives[i].getURL();
    }
    return urls;
  }

  /** helper method to remove urls that are not trusted */
  protected static CodeArchive[] excludeFromURLs(CodeArchive[] codeArchives, int index) {
    CodeArchive[] newCodeArchives = new CodeArchive[codeArchives.length - 1];
    System.arraycopy(codeArchives, 0, newCodeArchives, 0, index);
    System.arraycopy(codeArchives, index + 1, newCodeArchives, index, newCodeArchives.length - index);
    return newCodeArchives;
  }

  static void accumulateJars(List l, File f) {
    accumulateJars(l, f, true);
  }

  static void accumulateJars(List l, File f, boolean signatureRequired) {
    File[] files = f.listFiles(new FilenameFilter() {
        public boolean accept(File dir, String name) {
          return isJar(name);
        }
      });
    if (files == null) return;

    for (int i=0; i<files.length; i++) {
      try {
	if (files[i].getCanonicalPath().endsWith("jaas.jar")) {
	  // JAAS must be in the bootclass path, not in the classpath
	  continue;
	}
        l.add(new CodeArchive(newURL("file:"+files[i].getCanonicalPath()), signatureRequired));
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  static void accumulateClasspath(List l, String path) {
    // Jar file signature should be checked by default.
    accumulateClasspath(l, path, true);
  }

  static void accumulateClasspath(List l, String path, boolean signatureRequired) {
    String sep =  System.getProperty("file.separator", "/");
    if (path == null) return;
    List files = explodePath(path);
    for (int i=0; i<files.size(); i++) {
      try {
        String n = (String) files.get(i);

        if (!isJar(n) && !n.endsWith(sep)) {
          n = n + sep;
        }
        l.add(new CodeArchive(newURL(n), signatureRequired));
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  static final boolean isJar(String n) {
    return (n.endsWith(".jar") ||n.endsWith(".zip") ||n.endsWith(".plugin"));
  }

  static URL newURL(String p) throws MalformedURLException {
    try {
      URL u = new URL(p);
      return u;
    } catch (MalformedURLException ex) {
      return new URL("file:"+p);
    }
  }

  static final List explodePath(String s) {
    return explode(s, File.pathSeparatorChar);
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




