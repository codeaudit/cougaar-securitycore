/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

package org.cougaar.core.security.policy.webproxy;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintStream;

import java.lang.reflect.Method;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import org.cougaar.core.security.policy.webproxy.DamlURLStreamHandlerFactory;
import org.cougaar.core.security.policy.webproxy.DamlURLStreamHandler;
import org.cougaar.core.security.policy.webproxy.DamlURLConnection;


/**
 * This is a class that installs a proxy that intercepts the handling
 * of various java.net.URL calls.  
 *
 * Its advantage over the httpProxyand httpHost parameters, is that
 * for URL's where the proxy is not needed, the vanilla sun code
 * is used.  In the case where the proxy takes over, we are probably
 * not implementing the whole suite of URL services.  But I am hoping
 * that it is enough for loading the ontologies.
 *
 * One worry that I have is that I deduced much of this code by
 * looking at the java vm source.  Some of the results that I have
 * deduced would appear to be different than the documentation.  For
 * example, the documentation suggests that this proxy needs to be
 * installed before any other URL code occurs.  But testing and the
 * source indicates that they have taken the more reasonable course of
 * flushing the cache of URL handlers when a factory is installed.
 * Also I was having trouble figuring out that the "<system default
 * package>" described in the javadocs was actually
 *              sun.net.www.protocol
 * until I read the sources.
 *
 * Thank you George!! Without George's help this would have been much
 * harder. 
 */
public class WebProxyInstaller
{
  static private LoggingService _log = null;

  static {
    AccessController.doPrivileged(new LoadDamlURLStreamHandler());
  }

  /**
   * This method will allow us to use command line tools like jtp and
   * validator and have the access to URL's go through the proxy.
   * I have written scripts and put them in configs/test/bin.
   */
  public static void main(String [] args)
    throws Exception
  {
    try {
      WebProxyInstaller proxyInstaller = new WebProxyInstaller();
      proxyInstaller.install();
      if (args == null || args.length < 1) {
        System.out
          .println("Requires at least one argument - the class being invoked");
      }
      String className = args[0];
      String [] newargs = new String[args.length-1];
      for (int i = 1 ; i < args.length; i++) {
        newargs[i-1] = args[i];
      }

      Class cmdClass = Class.forName(className);
      String [] a = {"Fix", "this"};
      Class [] parameters = { a.getClass() };
      Method m = cmdClass.getDeclaredMethod("main", parameters);
      Object [] objectArgs = { newargs };
      m.invoke(null, objectArgs);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
 
  /**
   * This method installs the URL proxy.  
   *
   * Right now there is no uninstall.  I don't know how to remove my
   * proxy code but concievably we could change the URLStreamHandler
   * be able to stop using the proxy when it is told.
   *
   */
  public void install()
  {
    DamlURLStreamHandlerFactory factory = 
      new DamlURLStreamHandlerFactory();
    java.net.URL.setURLStreamHandlerFactory(factory);
    if (_log != null && _log.isDebugEnabled()) {
      _log.debug("proxy installed...");
    }
  }

  /**
   * Give this class a service broker so that it can start debugging.
   */
  public void installServiceBroker(ServiceBroker sb)
  {
    _log = (LoggingService)
      sb.getService(this, LoggingService.class, null);
    DamlURLStreamHandlerFactory.installServiceBroker(sb);
    DamlURLStreamHandler.installServiceBroker(sb);
    DamlURLConnection.installServiceBroker(sb);
    _log.debug("Logging Started for WebProxy Code");
  }

  /**
   * A simple utility test routine so that we can verify that this code works.
   */
  public void test(PrintStream out, String webpage)
  {
     try {
      out.println("-------------------------------------------------");
      out.println("Using openStream");
      URL weburl = new URL(webpage);
      InputStream input = weburl.openStream();
      out.println("Using stream " + input);
      BufferedReader reader = new BufferedReader(new InputStreamReader(input));
      String line = null;
      while ((line = reader.readLine()) != null) {
        out.println(line);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private static class LoadDamlURLStreamHandler implements PrivilegedAction
  {
    public Object run() {
      return new DamlURLStreamHandler();
    }
  }

}
