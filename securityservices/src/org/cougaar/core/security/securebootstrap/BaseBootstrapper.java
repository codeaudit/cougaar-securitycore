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

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.Arrays;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;

// Cougaar core services
import org.cougaar.bootstrap.Bootstrapper;

public class BaseBootstrapper
  extends Bootstrapper
{
  private String nodeName;

  protected String getNodeName() {
    return nodeName;
  }

  protected ClassLoader prepareVM(String classname, String[] args) {
    nodeName = parseNodename(args);
    ClassLoader cl = null;
    /*
      Setting up  policy & security manager
      if there is a policy and security manager then override the set 
      setPolicy & setSecurityManager methods. 
    */
    try {
      /* Set the Java policy for use by the security manager */
      if (loudness>0) {
	System.out.println("Setting policy");
      }
      setPolicy();

      /* Set the Java security manager */
      if (loudness>0) {
	System.out.println("Setting security manager");
      }
      setSecurityManager();

      /* Create a log file to report JAR file verification failures.
	 This is only used when a secure class loader is set. */
      if (loudness>0) {
	System.out.println("Creating Jar verification log");
      }
      createJarVerificationLog();

      /* Create the class loader. Load JAR files securely if
       * a secure class loader is used. */
      if (loudness>0) {
	System.out.println("Creating class loader");
      }
      cl = super.prepareVM(classname, args);
      if (loudness>0) {
	System.out.println("Class Loader:" + cl.getClass().getName());
      }
 
      /* Load cryptographic providers */
      if (loudness>0) {
	System.out.println("Loading cryptographic providers");
      }
      loadCryptoProviders(cl);
    }
    catch (Exception e) {
      System.err.println("Failed to launch "+classname+": ");
      e.printStackTrace();
    }

    return cl;
  }

  protected void launchMain(ClassLoader cl, String classname, String[] args) {
    if (loudness>0) {
      System.out.println("Starting " + classname + " in "
			 + System.getProperty("user.dir"));
      System.out.println("Arguments: ");
      for (int i = 0 ; i < args.length ; i++) {
	System.out.print(args[i] + " ");
      }
      System.out.println();
    }
    super.launchMain(cl, classname, args);
  }

  protected String parseNodename(String[] args) {
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

  protected void setPolicy() {
  }

  protected void setSecurityManager() {
  }

  protected void createJarVerificationLog() {
  }

  protected ClassLoader createClassLoader(List urlList) {
    if (loudness>0) {
      System.out.println("BaseBootstrapper.createClassLoader");
    }
    removeBootClasses(urlList);

    URL urls[] = (URL[]) urlList.toArray(new URL[urlList.size()]);
    return new BaseClassLoader(urls, loudness);
  }

  protected void loadCryptoProviders(ClassLoader cl)
  {
    StringBuffer configfile=new StringBuffer();
    String configproviderpath=
      System.getProperty("org.cougaar.core.security.crypto.cryptoProvidersFile");
    String sep = File.separator;
    if((configproviderpath==null)||(configproviderpath=="")) {
      configproviderpath=System.getProperty("org.cougaar.install.path");    
      if((configproviderpath!=null)||(configproviderpath!="")) {
	configfile.append(configproviderpath);
	configfile.append(sep+"configs"+sep+"security"+sep+"cryptoprovider.conf");
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
	      Class c = Class.forName(providerclassname, true, cl);
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

  /** Remove bootstrap jar files from the list of URLs.
   * The list of URLs constructed by looking in the $CIP/lib and $CIP/sys
   * directories may contain jar files which are already part of the boot class path.
   * These jar files should be loaded by the system class loader directly.
   * Here, we remove the boot jar files from the list.
   */
  protected void removeBootClasses(List urlList) {
    String bootclassPathProp = System.getProperty("sun.boot.class.path");
    if (loudness > 0) {
      System.out.println("Boot Class Path:" + bootclassPathProp);
    }
    StringTokenizer st = new StringTokenizer(bootclassPathProp, ":");
    ArrayList bootclassPath = new ArrayList();
    while(st.hasMoreElements()) {
      String s = st.nextToken();
      try {
	// Need to resolve symbolic names
	URL url = new URL("file", "", (new File(s)).getCanonicalPath());
	bootclassPath.add(url);
      }
      catch (Exception ex) {
	System.out.println("Unable to parse " + s + " url.");
      }
    }

    // Now, go through the list of URLs and remove the URLs which were
    // already specified in the boot class path.
    Iterator it = urlList.iterator();
    while (it.hasNext()) {
      URL aUrl = (URL) it.next();
      Iterator listIt = bootclassPath.iterator();
      while (listIt.hasNext()) {
	URL bootUrlElement = (URL) listIt.next();
	if (bootUrlElement.equals(aUrl)) {
	  // Don't add the bootclass URLs
	  if (loudness > 0) {
	    System.out.println("Removing " + aUrl.toString() + " from URL list");
	  }
	  it.remove();
          break;
	}
      }
    }
  }
}
