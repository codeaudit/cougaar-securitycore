package org.cougaar.core.security.policy.webproxy;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintStream;

import java.lang.reflect.Method;
import java.net.URL;

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

  /**
   * This method will allow us to use command line tools like jtp and
   * validator and have the access to URL's go through the proxy.
   * I have written scripts and put them in configs/test/bin.
   */
  public static void main(String [] args)
    throws Exception
  {
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
    System.out.println(cmdClass);
    String [] a = {"Fix", "this"};
    Class [] parameters = { a.getClass() };
    Method m = cmdClass.getDeclaredMethod("main", parameters);
    System.out.println("Method = " + m);
    Object [] objectArgs = { newargs };
    m.invoke(null, objectArgs);
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

}
