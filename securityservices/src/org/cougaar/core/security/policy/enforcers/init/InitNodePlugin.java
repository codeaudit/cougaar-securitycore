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

package org.cougaar.core.security.policy.enforcers.init;

import org.cougaar.core.security.policy.enforcers.ServletNodeEnforcer;
import org.cougaar.core.security.policy.enforcers.ULMessageNodeEnforcer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Reader;
import java.net.InetAddress;
import java.util.*;

import javax.servlet.*;
import javax.servlet.http.*;

import kaos.core.service.directory.DefaultKAoSAgentDescription;
import kaos.core.service.directory.KAoSAgentDescription;
import kaos.core.service.directory.KAoSAgentDirectoryServiceProxy;
import kaos.core.service.util.cougaar.CougaarLocator;
import kaos.core.util.VMIDGenerator;
import kaos.ontology.management.UnknownConceptException;

import safe.util.CougaarServiceRoot;

import org.cougaar.core.blackboard.*;
import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.*;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ServletService;
import org.cougaar.planning.ldm.policy.*;
import org.cougaar.util.*;

import org.cougaar.core.security.policy.EnforcerRegistrationException;

public class InitNodePlugin extends ComponentPlugin {

  private ServiceBroker _sb;
  private LoggingService _log;
  private String _hostname;
  private String _hostAddress;
  private ServletNodeEnforcer    _servletEnf;
  private ULMessageNodeEnforcer  _msgEnf;

  private ServletService servletService;
  private Servlet _messageServlet;
  private final String _messageServletPath = "/TestMessageMediationServlet";
  private Servlet _servletServlet;
  private final String _servletServletPath = "/TestServletMediationServlet";


  /*
   * This method does all the work of the TestEnforcer
   * (initialization).  The TestEnforcer is responsible for
   * initializing 
   *  1. a ServletNodeEnforcer and a ULMessageNodeEnforcer
   *  2. a servlet which gives an extremely simple view into what
   *     the Node enforcer is doing.
   */
  protected void setupSubscriptions()
  {
    try {
      BindingSite bs = getBindingSite();

      _sb = bs.getServiceBroker();

      _log = (LoggingService) _sb.getService(this,
                                            LoggingService.class,
                                            null);

      _log.info("InitNodePlugin.setupSubscriptions");

      // Construct the Enforcer

      // Registering the enforcer may lead to policies getting published
      // on the blackboard so we need to temporarily close it.
      getBlackboardService().closeTransactionDontReset();
      try {
        _servletEnf = new ServletNodeEnforcer(_sb);
        _servletEnf.registerEnforcer();

        _msgEnf     = new ULMessageNodeEnforcer(_sb,getAgents());
        _msgEnf.registerEnforcer();
      } catch (Throwable th) {
        _log.error("InitNodePlugin: Error registering the enforcers", th);
      } finally {
        getBlackboardService().openTransaction();
      }

      // Construct the servlet - throw away code for Ultralog
      _messageServlet = new TestMessageMediationServlet();
      _servletServlet = new TestServletMediationServlet();

      servletService = (ServletService)
        _sb.getService(this,
                      ServletService.class,
                      null);
      if (servletService == null) {
        throw new IllegalStateException("Unable to obtain ServletService");
      }
      servletService.register(_messageServletPath, _messageServlet);
      servletService.register(_servletServletPath, _servletServlet);

      //      getDirService(_sb);
    } catch (Exception e) {
      _log.error(".InitNodePlugin = problem in Initialization", e);
    }
  }

  /*
   * This is completely bogus and irritating - but I don't know the
   * right way to do it.  George will show me how it is really done.
   */
  public List getAgents()
  {
    return new Vector(getParameters());
  }

  /*
   * After setupSubscriptions there is really nothing for this
   * component to do.
   */
  protected void execute()
  {
    _log.info("InitNodePlugin.execute");
  }


  /*
   * An extremely simple servlet for some basic testing.
   */
  private class TestMessageMediationServlet extends HttpServlet 
  {
      
    /*
     * This function writes some initial introductory html before
     * calling the DummyNodeEnforcer for a test and some print
     * statements.  Then the function wraps up the html page.
     */
    public void doGet(HttpServletRequest req,
                      HttpServletResponse res) throws IOException 
    {
      _log.info("TestMessageMediationServlet: Doing Get...");
      try {
        PrintWriter out = res.getWriter();
        out.print("<html>\n" + 
                  "<head>\n" + 
                  "<TITLE>Message Passing Mediation Tests</TITLE>\n" + 
                  "</head>\n" + 
                  "<body>\n" + 
                  "<H1>Message Passing Mediation Check</H1>\n");
        List testAgents;
        try {
          out.print("<p>Getting agents to test from configuration file: "
                    + "DamlTestAgents</p>");
          testAgents = TestStringsFromFile("DamlTestAgents");
        } catch (Exception e) {
          out.print("<b> Could not read configuration file - see log</b>");
          _log.error("Problem obtaining agents for test routine", e);
          return;
        }

        _msgEnf.testEnforcer(out, testAgents);
        out.print("</body>\n" +
                  "</html>\n");
      } catch (UnknownConceptException e) {
        _log.error("Problem with Enforcer", e);
        IOException newe = new IOException("Problem with Enforcer");
        newe.initCause(e);
        throw newe;
      }
    }
  }

  /*
   * An extremely simple servlet for some basic testing.
   */
  private class TestServletMediationServlet extends HttpServlet 
  {
    /*
     * This function writes some initial introductory html before
     * calling the DummyNodeEnforcer for a test and some print
     * statements.  Then the function wraps up the html page.
     */
    public void doGet(HttpServletRequest req,
                      HttpServletResponse res) throws IOException 
    {
      PrintWriter out = res.getWriter();
      /*      try {
       * _servletEnf = new ServletNodeEnforcer(_sb);
       * _servletEnf.registerEnforcer();
       *
       *} catch (Exception e) {
       * IOException ioe = new IOException("Error registering servlet");
       * ioe.initCause(e);
       * throw ioe;
       *}
       */
      _log.info("TestServletMediation: Doing Get...");
      try {
        out.print("<html>\n" + 
                  "<head>\n" + 
                  "<TITLE>Servlet Mediation Tests</TITLE>\n" + 
                  "</head>\n" + 
                  "<body>\n" + 
                  "<H1>Servlet Mediation Check</H1>\n");
        out.print("<p> Reading configuration files DamlTestUris and " +
                  "DamlTestRoles to determine what to test</p>");

        _servletEnf.testEnforcer(out,
                                 TestStringsFromFile("DamlTestUris"),
                                 TestStringsFromFile("DamlTestRoles"));
        out.print("\n" + 
                  "</body>\n" +
                  "</html>\n");
      } catch (UnknownConceptException e) {
        out.print("<p>Problem with test - see log</p>");
        _log.error(".TestServletMediationServlet: Problem with Enforcer",
                   e);
        return;
      }
    }

  }

  /*
   * A hack for now until this plugin is removed and replaced with something 
   * more appropriate.
   */ 
  private List TestStringsFromFile(String filename)
    throws IOException
  {
    List vars = new Vector();
    ConfigFinder cf = ConfigFinder.getInstance();
    File file = cf.locateFile(filename);
    Reader reader = new FileReader(file);
    BufferedReader breader = new BufferedReader(reader);
    String line;
    while ((line = breader.readLine()) != null) {
      if (line.startsWith("#")) { continue; }
      vars.add(line);
    }
    return vars;
  }
}
