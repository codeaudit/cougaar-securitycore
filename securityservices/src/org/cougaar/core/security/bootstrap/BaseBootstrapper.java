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

package org.cougaar.core.security.bootstrap;

import java.io.*;
import java.net.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.zip.*;
import java.util.jar.*;
import java.security.*;
import java.security.cert.*;

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

public class BaseBootstrapper
{
  protected XURLClassLoader baseclassloader=null;
  public static int loudness = 0;
  private static String nodeName = null;
 
  static {
    String s = System.getProperty("org.cougaar.core.society.bootstrapper.loud");
    if ("true".equals(s)) {
      loudness = 1;
    } else if ("shout".equals(s)) {
      loudness = 2;
    } else if ("false".equals(s)) {
      loudness = 0;
    }
    // loudness=1;
  }

  private boolean isBootstrapped = false;

  public static void main(String[] args) {

    if (args.length <= 1) { // assemble command line from java VM properties
      String nodeClassName = "org.cougaar.core.node.Node";
	
      if (args.length == 1)
	nodeClassName = args[0];

      args = new String[4];
      args[0] = nodeClassName;
      args[1] = "-n";
      args[2] = System.getProperty("org.cougaar.node.name", "unknown-node");
      args[3] = "-c";
    }
  
    String[] launchArgs = new String[args.length - 1];
    System.arraycopy(args, 1, launchArgs, 0, launchArgs.length);
    BaseBootstrapper basebootstrapper=new BaseBootstrapper();
    basebootstrapper.launch(args[0], launchArgs);
  }
   
  /** Get the node name from the command line arguments */
  private static String getNodeName(String[] args) {
    int argc = args.length;
    String check = null;
    String next = null;
    boolean sawname = false;
    for( int x = 0; x < argc;){
      check = args[x++];
      if (! check.startsWith("-") && !sawname) {
        sawname = true;
        if ("admin".equals(check)) 
          nodeName = "Administrator";
        else
          nodeName = check;
      }
      else if (check.equals("-n")) {
        nodeName = args[x++];
        sawname = true;
      }
    }
    return nodeName;
  }

  public static String getNodeName() {
    return nodeName;
  }

  public void launch(String classname, String[] args){
    if (isBootstrapped) {
      throw new IllegalArgumentException("Circular Bootstrap!");
    }
    isBootstrapped = true;

    readProperties(System.getProperty("org.cougaar.properties.url"));
   
    String base = System.getProperty("org.cougaar.install.path");
    ArrayList l =  accumulateJarsandClasspath(base);
    CodeArchive[] codeArchives = (CodeArchive[]) l.toArray(new CodeArchive[l.size()]);
     String nodeName = getNodeName(args);
    
    /*
      Setting up  policy & security manager
      if there is a policy and security manager then override the set 
      setPolicy & setSecurityManager methods. 
    */
    try {
      /* Set the Java policy for use by the security manager */
      setPolicy();

      /* Set the Java security manager */
      setSecurityManager(nodeName);

      /* Create a log file to report JAR file verification failures.
	 This is only used when a secure class loader is set. */
      createJarVerificationLog(nodeName);

      /* Create the class loader. Load JAR files securely if
       * a secure class loader is used. */
      setClassLoader(codeArchives);
      
      /* New threads created by the node will use the Cougaar
	 class loader */
      Thread.currentThread().setContextClassLoader(baseclassloader);

      /* Load cryptographic providers */
      if (loudness>0) {
	System.out.println("Loading cryptographic providers");
      }
      loadCryptoProviders();
     
      Class realnode = baseclassloader.loadClass(classname);
     
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

  /**
   * Reads the properties from specified url
   **/
  public  void readProperties(String propertiesURL){
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

  protected void accumulateJars(List l, File f)
  {
    accumulateJars(l,f,false);
  }

  protected  void accumulateClasspath(List l, String path)
  {
    accumulateClasspath(l, path,false);
  }
  
  protected void accumulateJars(List l, File f,boolean signatureRequired) {
    File[] files = f.listFiles(new FilenameFilter() {
        public boolean accept(File dir, String name) {
          return isJar(name);
        }
      });
    if (files == null) return;

    for (int i=0; i<files.length; i++) {
      try {
        l.add(new CodeArchive(newURL("file:"+files[i].getCanonicalPath()),signatureRequired));
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  protected  void accumulateClasspath(List l, String path,boolean signatureRequired) {
    String sep =  System.getProperty("file.separator", "/");
    if (path == null) return;
    List files = explodePath(path);
    for (int i=0; i<files.size(); i++) {
      try {
        String n = (String) files.get(i);
        if (!isJar(n) && !n.endsWith(sep)) {
          n = n+sep;
          n = canonical(n); // Convert n to a canonical path, if possible
        }
        l.add(new CodeArchive(newURL(n),signatureRequired));
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  final boolean isJar(String n) {
    return (n.endsWith(".jar") ||n.endsWith(".zip") ||n.endsWith(".plugin"));
  }

  protected URL newURL(String p) throws MalformedURLException {
    try {
      URL u = new URL(p);
      return u;
    } catch (MalformedURLException ex) {
      return new URL("file:"+p);
    }
  }

  protected final List explodePath(String s) {
    return explode(s, File.pathSeparatorChar);
  }
  
  protected  final List explode(String s, char sep) {
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

  protected String canonical(String filename) {
    String ret = filename;
    if (!filename.startsWith("file:")) {
      File f = new File (filename);
      try {
        ret = f.getCanonicalPath() + File.separator;
      } catch (IOException ioe) {
        // file must not exist...
      }
    }
    //    System.out.println(filename+" CHANGED  to "+ret);
    return ret;
  }

  protected URL[] getURLs(CodeArchive[] codeArchives) {
    URL[] urls = new URL[codeArchives.length];
    for (int i=0; i<codeArchives.length; i++) {
      // Also create an array of URLs
      urls[i] = codeArchives[i].getURL();
    }
    return urls;
  }

  
  protected void createJarVerificationLog(String nodeName)
  {
  }

  public void setPolicy()
  {
  }

  public void setSecurityManager(String nodename)
  {
  }

  public void setClassLoader(CodeArchive[] codeArchives)
  {
    System.out.println("BaseBootstrapper.setClassLoader");
    baseclassloader= new CougaarClassLoader(getURLs(codeArchives));
  }

  public void loadCryptoProviders()
  {
    StringBuffer configfile=new StringBuffer();
    String configproviderpath=
      System.getProperty("org.cougaar.core.security.crypto.cryptoProvidersFile");
    String sep =  System.getProperty("file.separator", "/");
    if((configproviderpath==null)||(configproviderpath=="")) {
      configproviderpath=System.getProperty("org.cougaar.install.path");    
      if((configproviderpath!=null)||(configproviderpath!="")) {
	configfile.append(configproviderpath);
	configfile.append(sep+"configs"+sep+"common"+sep+"cryptoprovider.conf");
      }
      else {
	System.err.println("Error loading cryptographic providers: org.cougaar.install.path not set");
	return;
      }
    }
    else {
      configfile.append(configproviderpath);
    }
    
    File file=new File(configfile.toString());
    if(!file.exists()) {
      System.err.println("Cryptographic Provider Configuration file does not exist at given path ::"
			 +configfile.toString());
      return;
    }
    try {
      FileReader filereader=new FileReader(file);
      BufferedReader buffreader=new BufferedReader(filereader);
      String linedata=new String();
      int index=0;
      String providerclassname="";
      while((linedata=buffreader.readLine())!=null) {
	linedata.trim();
	if(linedata.startsWith("#")) {
	  continue;
	}
	if(linedata.startsWith("security.provider")) {
	  index=linedata.indexOf('=');
	  if(index!=-1) {
	    providerclassname=linedata.substring(index+1);
	    if (loudness > 0) {
	      System.out.println("Loading provider " + providerclassname);
	    }
	    try {
	      Class c = Class.forName(providerclassname,true,baseclassloader);
	      Object o = c.newInstance();
	      if (o instanceof java.security.Provider) {
		Security.addProvider((java.security.Provider) o);
	      }
	    } 
	    catch(Exception e) {
	      System.err.println("Error loading security provider (" + e + ")"); 
	    }
	  }
	}
      }
    }
    catch(FileNotFoundException fnotfoundexp) {
      System.err.println("cryptographic provider configuration file not found");
      fnotfoundexp.printStackTrace();
    }
    catch(IOException ioexp) {
      System.err.println("Cannot read cryptographic provider configuration file: " + ioexp);
      ioexp.printStackTrace();
    }
    if (loudness>0) {
      printProviderProperties();
    }
  }

  public static void printProviderProperties() {
    Provider[] pv = Security.getProviders();
    for (int i = 0 ; i < pv.length ; i++) {
      System.out.println("Provider[" + i + "]: "
			 + pv[i].getName() + " - Version: " + pv[i].getVersion());
      System.out.println(pv[i].getInfo());
      // List properties
      String[] properties = new String[1];
      properties = (String[]) pv[i].keySet().toArray(properties);
      Arrays.sort(properties);
      for (int j = 0 ; j < properties.length ; j++) {
	String key, value;
	key = (String) properties[j];
	value = pv[i].getProperty(key);
	System.out.println("Key: " + key + " - Value: " + value);
      }
    }
  }

  protected ArrayList accumulateJarsandClasspath(String base)
  {
    ArrayList l=new ArrayList();
    accumulateClasspath(l, System.getProperty("org.cougaar.class.path"));
    accumulateJars(l, new File(base,"lib"));
    accumulateJars(l, new File(base,"plugins"));

    String sysp = System.getProperty("org.cougaar.system.path");
    if (sysp!=null) {
      accumulateJars(l, new File(sysp));
    }
      
    accumulateJars(l,new File(base,"sys"));
    if(BaseBootstrapper.loudness>0) {
      System.out.println("list of jars accumulated is ::");
      printlist(l);
    }
    return l;
  }

  public void printlist(ArrayList l)
  {
    if(loudness>1) {
      Iterator i=l.iterator();
      CodeArchive codearc=null;
      for(;i.hasNext();) {
	codearc=(CodeArchive)i.next();
	System.out.println("Element in list  is::"+codearc.getURL().toString()); 
      }
    }
  }
}
