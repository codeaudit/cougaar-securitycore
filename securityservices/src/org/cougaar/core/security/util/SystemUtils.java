/*
 * <copyright>
 *  Copyright 1997-2002 Network Associates
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
package org.cougaar.core.security.util;

import java.net.InetAddress;
import java.util.List;
import java.util.ArrayList;

public class SystemUtils {
  
  public static String getNodeName(){
    return System.getProperty( "org.cougaar.node.name" ); 
  }
  public static List getCmdLineArgs(){
    List args = new ArrayList();
    String arg = System.getProperty( "org.cougaar.validate.jars" );
    if( arg != null ) args.add( arg );
    arg = System.getProperty( "org.cougaar.node.name" );
    if( arg != null ) args.add( arg );
    arg = System.getProperty( "org.cougaar.config" );
    if( arg != null ) args.add( arg );
    arg = System.getProperty( "org.cougaar.config.server" );
    if( arg != null ) args.add( arg );
    arg = System.getProperty( "org.cougaar.name.server" );
    if( arg != null ) args.add( arg );
    arg = System.getProperty( "org.cougaar.name.server.port" );
    if( arg != null ) args.add( arg );
    arg = System.getProperty( "org.cougaar.filename" );
    if( arg != null ) args.add( arg );
    arg = System.getProperty( "org.cougaar.experiment.id" );
    if( arg != null ) args.add( arg );
    return args;
  }
  
  public static List getEnvs(){
    List envVars = new ArrayList();
    StringBuffer sb = new StringBuffer( "CLASSPATH=" );
    sb.append( System.getProperty( "java.class.path" ) );
    sb.append( System.getProperty( "path.separator" ) );
    sb.append( System.getProperty( "sun.boot.class.path" ) );
    envVars.add( sb.toString() );
    envVars.add( "LIBRARY_PATH=" + System.getProperty( "java.library.path" ) );
    envVars.add( "HOME=" + System.getProperty( "user.home" ) );
    envVars.add( "USER=" + System.getProperty( "user.name" ) );
    try {
      String host = InetAddress.getLocalHost().getHostName();
      envVars.add( "HOST=" + host );
    }
    catch( Exception e ) {
      e.printStackTrace();
    }
    return envVars;
  }
  
  public static String getVMInfo(){
    String vmInfo = System.getProperty( "java.vm.name" ) + " " +
                    System.getProperty( "java.vm.version" );
    return vmInfo;        
  }
  
  public static String getJavaHome(){
    return System.getProperty( "java.home" ); 
  }
  
    private static String CLASS_PATH = "java.class.path";
    private static String PATH = "java.path";
    private static String RUNTIME_NAME = "java.runtime.name";
    private static String BOOT_LIB_PATH = "sun.boot.library.path";
    private static String VM_VERSION = "java.vm.version";
    private static String USER_COUNTRY = "user.country";
    private static String OS_PATCH_LEVEL = "sun.os.patch.level";
    private static String USER_DIR = "user.dir";
    private static String RUNTIME_VERSION = "java.runtime.version";
    private static String OS_ARCH = "os.arch";
    private static String VM_SPEC_VENDOR = "java.vm.specification.vendor";
    private static String OS_NAME = "os.name";
    private static String LIB_PATH = "java.library.path";
    private static String CLASS_VERSION = "java.class.version";
    private static String OS_VERSION = "os.version";
    private static String SPEC_VERSION = "java.specification.version";
    private static String USER_NAME = "user.name";
    private static String JAVA_HOME = "java.home";
    private static String JAVA_VERSION = "java.version";
    private static String BOOT_CLASS_PATH = "sun.boot.class.path";
    
    private String listOfProperties[] = { CLASS_PATH,
                                          PATH,
                                          RUNTIME_NAME,
                                          BOOT_LIB_PATH,
                                          VM_VERSION,
                                          USER_COUNTRY,
                                          OS_PATCH_LEVEL,
                                          USER_DIR,
                                          RUNTIME_VERSION,
                                          OS_ARCH,
                                          VM_SPEC_VENDOR,
                                          OS_NAME,
                                          LIB_PATH,
                                          CLASS_VERSION,
                                          OS_VERSION,
                                          SPEC_VERSION,
                                          USER_NAME,
                                          JAVA_HOME,
                                          JAVA_VERSION,
                                          BOOT_CLASS_PATH };

  

}
