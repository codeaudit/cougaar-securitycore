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


package org.cougaar.core.security.policy.enforcers.init;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Reader;
import java.util.List;
import java.util.Vector;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import kaos.ontology.management.UnknownConceptException;

import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.policy.enforcers.ServletNodeEnforcer;
import org.cougaar.core.security.policy.mediator.OwlMessagePolicyMediator;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ServletService;
import org.cougaar.util.ConfigFinder;

public class InitNodePlugin extends ComponentPlugin {

  private ServiceBroker _sb;
  private LoggingService _log;
  private ServletNodeEnforcer    _servletEnf;
  private OwlMessagePolicyMediator  _msgEnf;

  private final String _messageServletPath = "/TestMessageMediationServlet";
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

      if (_log.isInfoEnabled()) {
        _log.info("InitNodePlugin.setupSubscriptions");
      }

      // Construct the Enforcer

      // Registering the enforcer may lead to policies getting published
      // on the blackboard so we need to temporarily close it.
      getBlackboardService().closeTransactionDontReset();
      _servletEnf = new ServletNodeEnforcer(_sb);
      try {
        _servletEnf.registerEnforcer();
      }
      catch (Exception e) {
        _servletEnf = null;
        if (_log.isWarnEnabled()) {
          _log.warn("Unable to register enforcer. InitNodePlugin running without policy");
        }
      } finally {
        getBlackboardService().openTransaction();
      }

      getBlackboardService().closeTransactionDontReset();
      _msgEnf     = new OwlMessagePolicyMediator(_sb,getAgents());
      try {
        _msgEnf.registerEnforcer();
      } catch (Exception e) {
         _msgEnf = null;
        if (_log.isWarnEnabled()) {
          _log.warn("No guard. InitNodePlugin running without policy");
        }
      } finally {
        getBlackboardService().openTransaction();
      }

      ServletService servletService = (ServletService)
        _sb.getService(this,
                      ServletService.class,
                      null);
      if (servletService == null) {
        if (_log.isWarnEnabled()) {
          _log.warn("Unable to obtain ServletService. Test mediation servlets will not be enabled. "
              + " This is ok as long as mediation tests are not performed");
        }
      }
      else {
        // Construct the servlet - throw away code for Ultralog
        Servlet _messageServlet = new TestMessageMediationServlet();
        Servlet _servletServlet = new TestServletMediationServlet();
        servletService.register(_messageServletPath, _messageServlet);
        servletService.register(_servletServletPath, _servletServlet);
        
        _sb.releaseService(this, ServletService.class, servletService);
      }

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
    if (_log.isInfoEnabled()) {
      _log.info("InitNodePlugin.execute");
    }
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
