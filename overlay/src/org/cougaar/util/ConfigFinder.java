/*
 * <copyright>
 *  Copyright 1997-2003 BBNT Solutions, LLC
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
 */
package org.cougaar.util;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.zip.*;
import org.apache.xerces.parsers.DOMParser;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.EntityResolver;
import org.w3c.dom.Document;

//import org.apache.log4j.*;
import org.cougaar.util.log.*;

/**
 * ConfigFinder provides utilitites to search for a named file in
 * several specified locations, returning the first location where a
 * file by that name is found.
 *
 * Files are found and opened by the open() method. open() tries to
 * find the file using each of the elements of org.cougaar.config.path. The
 * elements of org.cougaar.config.path are separated by semicolons and
 * interpreted as URLs. The URLs in org.cougaar.config.path are interpreted
 * relative to the directory specified by org.cougaar.install.path. Several
 * special tokens may appear in these URLs:
 *
 * $INSTALL signifies file:<org.cougaar.install.path>
 * $CONFIG signifies <org.cougaar.config>
 * $CWD signifies <user.dir>
 * $HOME signifies <user.home>
 * $MOD signifies the name of a Cougaar module - a sub-directory of $INSTALL
 *
 * The default value for org.cougaar.config.path is defined in the static
 * variable defaultConfigPath:
 *   $CWD;$HOME/.alp;$INSTALL/configs/$CONFIG;$INSTALL/configs/common
 *
 * If a value is specified for org.cougaar.config.path that ends with a
 * semicolon, the above default is appended to the specified
 * value. The URLs in org.cougaar.config.path are interpreted relative to
 * $INSTALL. URLs may be absolute in which case some or all of the
 * base URL may be ignored.
 *
 * By default, $MOD is not set. However, when an object requests
 * a ConfigFinder, it may specify a String value for $MOD. If specified,
 * the search path used is augmented, adding 4 directories to the start
 * of the search path:
 * <ul>
 * <li>$INSTALL/$MOD/configs/$CONFIG</li>
 * <li>$INSTALL/$MOD/configs</li>
 * <li>$INSTALL/$MOD/data/$CONFIG</li>
 * <li>$INSTALL/$MOD/data</li>
 * </ul>
 * <br>
 *
 * Enable INFO level logging on org.cougaar.core.util.ConfigFinder to turn on
 * additional information on usage of ConfigFinder.
 * @property org.cougaar.install.path Used as the base path for config file finding.
 * @property org.cougaar.config.path The search path for config files.  See the class
 * documentation for details.
 * @property org.cougaar.core.util.ConfigFinder.verbose When set to <em>true</em>, report
 * progress while finding each config file.
 * @property org.cougaar.config The configuration being run, for example minitestconfig or small-135.
 * Setting this property means that CIP/configs/<value of this property> will be searched before configs/common 
 **/
public class ConfigFinder {
  private List configPath = new ArrayList(11);
  private final  Map properties; // initialized by all constructors

  private Logger logger = null; // use getLogger to access

  protected final synchronized Logger getLogger() {
    if (logger == null) {
      logger = Logging.getLogger(ConfigFinder.class);
    }
    return logger;
  }

  public ConfigFinder() {
    this(Configuration.getConfigPath(), Configuration.getDefaultProperties());
  }

  public ConfigFinder(String s) {
    this(s, Configuration.getDefaultProperties());
  }

  /**
   * Construct a ConfigFinder that will first search within
   * the specified module, and then in the directories on the 
   * given search path, using the default Property substitutions.<br>
   *
   * When searching the given module, we search the following 4
   * directories (if defined) before any other directories:
   * <ul>
   * <li>$INSTALL/$module/configs/$CONFIG</li>
   * <li>$INSTALL/$module/configs</li>
   * <li>$INSTALL/$module/data/$CONFIG</li>
   * <li>$INSTALL/$module/data</li>
   * </ul>
   **/
  public ConfigFinder(String module, String path) {
    this(module, path, Configuration.getDefaultProperties());
  }

  public ConfigFinder(String s, Map props) {
    this(null, s, props);
  }

  /**
   * Construct a ConfigFinder that will first search within
   * the specified module, and then in the directories on the 
   * given search path, using the given Property substitutions.<br>
   *
   * When searching the given module, we search the following 4
   * directories (if defined) before any other directories:
   * <ul>
   * <li>$INSTALL/$module/configs/$CONFIG</li>
   * <li>$INSTALL/$module/configs</li>
   * <li>$INSTALL/$module/data/$CONFIG</li>
   * <li>$INSTALL/$module/data</li>
   * </ul>
   **/
  public ConfigFinder(String module, String s, Map props) {
    if (getLogger().isDebugEnabled()) {
      getLogger().debug("ConfigFinder class: " + this.getClass().getName());
    }

    properties = new HashMap();
    if (props != null) properties.putAll(props);

    if (s == null) {
      s = Configuration.getConfigPath();
    } else {
      s = s.replace('\\', '/'); // Make sure its a URL and not a file path
      // append the default if we end with a ';'
      if (s.endsWith(";")) s += Configuration.getConfigPath();
    }

    Vector mv = null;
    if (module != null) {
      properties.put("MOD", module);
      // Tack on to the front of the search path CIP/module/configs/$CONFIG
      // CIP/module/configs, CIP/module/data/CONFIG, CIP/module/data
      mv = new Vector(4);
      mv.add("$INSTALL/$MOD/configs/$CONFIG");
      mv.add("$INSTALL/$MOD/configs");
      mv.add("$INSTALL/$MOD/data/$CONFIG");
      mv.add("$INSTALL/$MOD/data");
    }

    Vector v;

    if (mv != null)
      v = new Vector(mv);
    else 
      v = new Vector();
    
    {
      String[] els = s.trim().split("\\s*;\\s*");
      for (int i = 0; i<els.length; i++) {
        v.add(els[i]);
      }
    }

    int l = v.size();
    for (int i = 0; i < l; i++) {
      appendPathElement((String) v.elementAt(i));
    }

    configPath = Collections.unmodifiableList(configPath); //  make it unmodifiable
    if (getLogger().isInfoEnabled()) {
      StringBuffer sb = new StringBuffer("ConfigPath = ");
      for (Iterator it = configPath.iterator(); it.hasNext();) {
        String se = it.next().toString();
        sb.append(se);
        if (it.hasNext()) sb.append(", ");
      }
      getLogger().info(sb.toString());
    }
  }

  /** get the config path as an unmodifiable List of URL instances
   * which describes, in order, the set of base locations searched by
   * this instance of the ConfigFinder.
   * Contrast with Configuration.getConfigPath() which returns the
   * vm's default path.
   **/
  public List getConfigPath() { return configPath; }

  /** @return the current Cougaar Install Path 
   * @deprecated Use Configuration.getInstallURL();
   **/
  public URL getInstallURL() { return Configuration.getInstallURL(); }
  /** @return the current config directory (or common, if undefined) 
   * @deprecated Use Configuration.getConfigURL();
   **/
  public URL getConfigURL() { return Configuration.getConfigURL(); }

  protected final String substituteProperties(String s) {
    return Configuration.substituteProperties(s, properties);
  }

  protected final void appendPathElement(URL url) {
    if (!configPath.contains(url)) {
      configPath.add(url);
    }
  }

  protected final void appendPathElement(String el) {
    try {
      appendPathElement(resolveName(el));
    } catch (MalformedURLException mue) {
      getLogger().warn("Ignoring unparsable path element \""+el+"\"", mue);
    }
  }

  /**
   * Locate an actual file in the config path. This will skip over
   * elements of org.cougaar.config.path that are not file: urls.
   **/
  public File locateFile(String aFilename) {
    for (int i = 0 ; i < configPath.size() ; i++) {
      URL url = (URL) configPath.get(i);
      if (url.getProtocol().equals("file")) {
        try {
          URL fileURL = new URL(url, aFilename);
          File result = new File(fileURL.getFile());
          if (result.exists()) {
            traceLog(aFilename, url);
            return result;
          }
        } catch (MalformedURLException mue) {
          continue;
        }
      }
    }
    traceLog(aFilename, null);
    return null;
  }

  /**
   * Resolve a logical reference to a URL, e.g.
   * will convert "$INSTALL/configs/common/foo.txt" to
   * "file:/opt/cougaar/20030331/configs/common/foo.txt"
   * or somesuch.
   * @returns null if unresolvable.
   **/
  public URL resolveName(String logicalName) throws MalformedURLException{
    return Configuration.urlify(Configuration.substituteProperties(logicalName,properties));
  }

  /**
   * Opens an InputStream to access the named file. The file is sought
   * in all the places specified in configPath.
   * @throws IOException if the resource cannot be found.
   **/
  public InputStream open(String aURL) throws IOException {
    for (int i = 0 ; i < configPath.size() ; i++) {
      URL base = (URL) configPath.get(i);
      try {
        URL url = new URL(base, aURL);
        InputStream is = url.openStream();
        if (is == null) continue; // Don't return null
        traceLog(aURL, base);
        return is;
      } 
      catch (MalformedURLException mue) {
        if (getLogger().isDebugEnabled()) {
          getLogger().debug("Exception while looking for "+aURL+" at "+base, mue);
        }
        continue;
      }
      catch (IOException ioe) {
        if (getLogger().isDebugEnabled()) {
          getLogger().debug("Exception while looking for "+aURL+" at "+base, ioe);
        }
        continue;
      }
    }

    traceLog(aURL, null);
    /*
    StringTokenizer st = new StringTokenizer (aURL, "-.");
    String sb = st.nextToken() + ".zip";
    try {
      File file = locateFile(sb);
      if (file != null) {
        return openZip(aURL, file.toString());
      }
    } catch (IOException ioe) {
      if (getLogger().isDebugEnabled()) {
        getLogger().debug("Exception while looking for "+aURL+" in zip "+sb, ioe);
      }
    } catch (NullPointerException npe) {
      if (getLogger().isDebugEnabled()) {
        getLogger().debug("Exception while looking for "+aURL+" in zip "+sb, npe);
      }
    }
    */

    throw new FileNotFoundException(aURL);
  }

  /**
   * Attempt to find the URL which would be opened by the open method.
   * Note that this must actually attempt to open the various URLs
   * under consideration, so this is <em>not</em> an inexpensive operation.
   **/
  public URL find(String aURL) throws IOException {
    for (int i = 0 ; i < configPath.size() ; i++) {
      URL base = (URL) configPath.get(i);
      try {
        URL url = new URL(base, aURL);
        InputStream is = url.openStream();
        if (is == null) continue; // Don't return null
        is.close();
        traceLog(aURL, base);
        return url;
      }
      catch (MalformedURLException mue) {
        continue;
      }
      catch (IOException ioe) {
        continue;
      }
    }
    //if (getLogger().isInfoEnabled()) 
    {
      // it isn't really an error, but I think we'd like to see these.
      getLogger().warn("Failed to find "+aURL);
    }
    traceLog(aURL, null);

    return null;
  }

  public InputStream openZip (String aURL, String aZIP) 
    throws IOException
  {
    ZipFile zip = null;
    InputStream retval = null;
    try {
      zip = new ZipFile(aZIP);
      Enumeration zipfiles = zip.entries();
      while (zipfiles.hasMoreElements()){
	ZipEntry file = (ZipEntry)zipfiles.nextElement();
	try {
	  if (file.getName().equals(aURL)) {
	    retval = zip.getInputStream(file);
	  } else if (file.getName().endsWith (".cfg")) {
	    InputStream is = zip.getInputStream(file);
	    BufferedReader in = new BufferedReader(new InputStreamReader(is));
	    while (in.ready()) {
	      String text = in.readLine();
              // this is seriously wrong (MIK)
	      //appendPathElement(text.substring(0, text.lastIndexOf(File.separator)));
	    }
	  }
	} catch (IOException ioe) {	
	  continue;
	}
      }
      return retval;
    } catch (ZipException ioe) {
    }
    throw new FileNotFoundException(aZIP);
  }

  public Document parseXMLConfigFile(String xmlfile) throws IOException {
    InputStream istream = null;
    istream = open(xmlfile);
    if (istream == null) {
      throw new RuntimeException("Got null InputStream opening file " + xmlfile);
    }
    return parseXMLConfigFile(istream, xmlfile);
  }

  protected Document parseXMLConfigFile(InputStream isstream, String xmlfile)
    throws IOException {
    DOMParser parser = new DOMParser();
    parser.setEntityResolver(new ConfigResolver());
    InputSource is = null;
    try {
      is = new InputSource(isstream);
      if (is == null) {
         throw new RuntimeException("Got null InputSource from input stream for file " + xmlfile);
      }
      parser.parse(is);
    } catch (SAXException e) {
      getLogger().error("Exception parsing XML file \""+xmlfile+"\"", e);
    }

    return parser.getDocument();
  }


  // hash of the default module config finders
  private static Map moduleConfigFinders;

  // Singleton pattern
  private static ConfigFinder defaultConfigFinder = null;

  private static Class getConfigFinderClass() {
    String configFinderClassName = 
      System.getProperty("org.cougaar.util.ConfigFinder.ClassName");
    Class theClass = ConfigFinder.class;
    if (configFinderClassName != null) {
      try {
	theClass = Class.forName(configFinderClassName);
      }
      catch (Exception e) {
	throw new RuntimeException("Not a valid ConfigFinder class: "
				   + configFinderClassName, e);
      }
      if (!ConfigFinder.class.isAssignableFrom(theClass)) {
	throw new RuntimeException(ConfigFinder.class.getName() + " should be a superclass of "
				   + configFinderClassName);
      }
    }
    return theClass;
  }

  private static ConfigFinder getConfigFinderInstance(String path) {
    Class cls = getConfigFinderClass();
    Class paramCls[] = new Class[] { String.class };
    Object paramVal[] = new Object[] { path };

    try {
      return (ConfigFinder) cls.getConstructor(paramCls).newInstance(paramVal);
    }
    catch (Exception e) {
      throw new RuntimeException("Unable to instantiate ConfigFinder", e);
    }
  }

  private static ConfigFinder getConfigFinderInstance(String module, String path) {
    Class cls = getConfigFinderClass();
    Class paramCls[] = new Class[] {String.class, String.class};
    Object paramVal[] = new Object[] { module, path };

    try {
      return (ConfigFinder) cls.getConstructor(paramCls).newInstance(paramVal);
    }
    catch (Exception e) {
      throw new RuntimeException("Unable to instantiate ConfigFinder");
    }
  }

  private synchronized static ConfigFinder getDefaultConfigFinder() {
    if (defaultConfigFinder == null) {
      try {
	defaultConfigFinder =
	  (ConfigFinder) getConfigFinderClass().newInstance();    
      }
      catch (Exception e) {
	throw new Error("Unable to instantiate ConfigFinder", e);
      }
    }
    return defaultConfigFinder;
  }

  /**
   * Return the default static instance of the ConfigFinder,
   * configured using the system properties.
   **/
  public static ConfigFinder getInstance() {
    return getDefaultConfigFinder();
  }

  /**
   * Return a new ConfigFinder that uses the system properties
   * for most configuration details, adding the four module-specific
   * directories to the front of the search path.
   **/
  public static ConfigFinder getInstance(String module) {
    if (module == null || module.equals("")) {
      return getDefaultConfigFinder();
    }
    
    String config_path = System.getProperty("org.cougaar.config.path");
    if (config_path != null && 
	config_path.charAt(0) == '"' &&
	config_path.charAt(config_path.length()-1) == '"')	
      config_path = config_path.substring(1, config_path.length()-1);
    
    // Build static hash on $module of these
    if (moduleConfigFinders == null)
      moduleConfigFinders = new HashMap();

    ConfigFinder mcf = (ConfigFinder)moduleConfigFinders.get(module);
    if (mcf == null) {
      mcf = getConfigFinderInstance(module, config_path);
      moduleConfigFinders.put(module, mcf);
    }
    return mcf;
  }


  class ConfigResolver implements EntityResolver {
    public InputSource resolveEntity (String publicId, String systemId) {
      URL url = null;

      try {
	url = new URL(systemId);
      } catch(Exception e) {}

      String filename = url.getFile();

      // Convert any '\'s to '/'s.
      filename = filename.replace('\\', '/');

      filename = filename.substring(filename.lastIndexOf("/") + 1, filename.length());

      InputSource is = null;
      try {
	InputStream istream = open(filename);
        if (istream == null) {
	  throw new RuntimeException("Got null input stream opening file " + filename);
        }
        is = new InputSource(istream);
      } catch(IOException e) {
        getLogger().error("Error getting input source for file \""+filename+"\"", e);
       }
      
      if(is == null) {
        getLogger().error("Null InputSource for file \""+filename+"\"");
      }

      return is;
   } 
  }

  /** Hack for logging nice messages when tracing is enabled.
   * Looks back up the stack for method and origin points.
   **/
  // this could be static except that the logger isn't static right now.
  private void traceLog(Object name, Object value) {
    if (getLogger().isInfoEnabled()) {
      Throwable t = new Throwable();
      StackTraceElement[] st = t.getStackTrace();
      String frame = "unknown";
      String method = "unknown";
      for (int i = 0; i<st.length; i++) {
        StackTraceElement se = st[i];
        if (i == 1) {
          method = se.getMethodName();
        }
        String cn = se.getClassName();
        if ((!cn.startsWith("org.cougaar.util.")) &&
            (!cn.startsWith("org.apache."))) {
          frame = se.toString();
          break;
        }
      }
      getLogger().info(method+"("+name.toString()+")="+value+" from "+frame);
    }
  }

}
