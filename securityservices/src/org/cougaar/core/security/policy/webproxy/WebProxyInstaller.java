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


package org.cougaar.core.security.policy.webproxy;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;


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
