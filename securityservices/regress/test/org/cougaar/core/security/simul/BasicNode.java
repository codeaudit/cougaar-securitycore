/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * Created on September 12, 2001, 10:55 AM
 */

package test.org.cougaar.core.security.simul;

import junit.framework.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;

// Cougaar core services
import org.cougaar.core.service.*;
import org.cougaar.core.component.*;

// Cougaar security services
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.securebootstrap.*;

public class BasicNode
{
  private SecurityServiceProvider secProvider;
  private ServiceBroker serviceBroker;

  protected final static List excludedJars = new ArrayList();
  protected final static int loudness;

  static {
    excludedJars.add("javaiopatch.jar");
    excludedJars.add("bootstrap.jar");
    
    String s = System.getProperty("org.cougaar.bootstrap.excludeJars");
    if (s != null) {
      String files[] = s.split(":");
      for (int i=0; i<files.length; i++) {
        excludedJars.add(files[i]);
      }
    }
    loudness = 2;
  }

  public BasicNode() {
    List l = computeURLs();
    Assert.assertNotNull("Could not get jar file URLs", l);
    ClassLoader cl = createClassLoader(l);
    Assert.assertNotNull("Could not create class loader", cl);
    loadCryptoProviders(cl);

    // Initialize Security Service Provider
    secProvider = new SecurityServiceProvider();
    Assert.assertNotNull("Could not initialize SecurityServiceProvider", secProvider);

    // Get Service Broker
    serviceBroker = secProvider.getServiceBroker();
    Assert.assertNotNull("Could not get ServiceBroker", serviceBroker);

    // Create Guard
    GuardFactory gf = new GuardFactory(serviceBroker);
    Assert.assertNotNull("Could not initialize Guard", gf);
  }

  public ServiceBroker getServiceBroker() {
    return serviceBroker;
  }

  public SecurityServiceProvider getSecurityServiceProvider() {
    return secProvider;
  }
  
  protected ClassLoader createClassLoader(List l) {
    if (loudness>0) {
      System.out.println("BaseBootstrapper.createClassLoader");
    }
    URL urls[] = (URL[]) l.toArray(new URL[l.size()]);
    return new BaseClassLoader(urls, loudness);
  }
 
  protected List computeURLs() {
    return filterURLs(findURLs());
  }

  protected List findURLs() {
    List l = new ArrayList();

    String base = System.getProperty("org.cougaar.install.path");
    l.addAll(findJarsInClasspath(System.getProperty("org.cougaar.class.path")));

    // no longer accumulate classpath
    //findJarsInClasspath(System.getProperty("java.class.path"));

    // we'll defer to system's classpath if we don't find it anywhere
    l.addAll(findJarsInDirectory(new File(base,"lib")));
    l.addAll(findJarsInDirectory(new File(base,"plugins")));

    String sysp = System.getProperty("org.cougaar.system.path");
    if (sysp!=null) {
      l.addAll(findJarsInDirectory(new File(sysp)));
    }

    l.addAll(findJarsInDirectory(new File(base,"sys")));
    return l;
  }

  protected List filterURLs(List l) {
    List o = new ArrayList();
    for (Iterator it = l.iterator(); it.hasNext(); ) {
      URL u = (URL) it.next();
      if (checkURL(u)) {
        o.add(u);
      } else {
      }
    }
    return o;
  }

  /** Check to see if a specific URL should be included in the bootstrap
   * classloader's URLlist.  The default implementation checks each url
   * against the list of excluded jars.
   **/
  protected boolean checkURL(URL url) {
    String u = url.toString();
    int l = excludedJars.size();
    for (int i = 0; i<l; i++) {
      String tail = (String) excludedJars.get(i);
      if (u.endsWith(tail)) return false;
    }
    return true;
  }


  /** Gather jar files found in the directory specified by the argument **/
  protected List findJarsInDirectory(File f) {
    List l = new ArrayList();
    File[] files = f.listFiles(new FilenameFilter() {
        public boolean accept(File dir, String name) {
          return isJar(name);
        }
      });

    if (files == null) return l;

    for (int i=0; i<files.length; i++) {
      try {
        l.add(newURL("file:"+files[i].getCanonicalPath()));
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
    return l;
  }

  /** gather jar files listed in the classpath-like specification **/
  protected List findJarsInClasspath(String path) {
    List l = new ArrayList();
    if (path == null) return l;
    String files[] = path.split(File.pathSeparator);
    for (int i=0; i<files.length; i++) {
      try {
        String n = files[i];
        if (!isJar(n) && !n.endsWith("/")) {
          n = n+"/";
          n = canonicalPath(n); // Convert n to a canonical path, if possible
        }
        l.add(newURL(n));
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
    return l;
  }

  /** convert a directory name to a canonical path **/
  protected final String canonicalPath(String filename) {
    String ret = filename;
    if (!filename.startsWith("file:")) {
      File f = new File (filename);
      try {
        ret = f.getCanonicalPath() + File.separator;
      } catch (IOException ioe) {
        // file must not exist...
      }
    }
    return ret;
  }

  /** @return true iff the argument appears to name a jar file **/
  protected boolean isJar(String n) {
    return (n.endsWith(".jar") ||n.endsWith(".zip") ||n.endsWith(".plugin"));
  }

  /** Convert the argument into a URL **/
  protected URL newURL(String p) throws MalformedURLException {
    try {
      URL u = new URL(p);
      return u;
    } catch (MalformedURLException ex) {
      return new URL("file:"+p);
    }
  }
 
  protected void loadCryptoProviders(ClassLoader cl)
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

}
