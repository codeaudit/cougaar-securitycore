package org.cougaar.core.security.policy.enforcers.init;

import org.cougaar.core.security.policy.enforcers.ServletNodeEnforcer;
import org.cougaar.core.security.policy.enforcers.ULMessageNodeEnforcer;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.util.*;

import javax.servlet.*;
import javax.servlet.http.*;

import kaos.core.service.directory.DefaultKAoSAgentDescription;
import kaos.core.service.directory.KAoSAgentDescription;
import kaos.core.service.directory.KAoSAgentDirectoryServiceProxy;
import kaos.core.service.util.cougaar.CougaarLocator;
import kaos.core.util.VMIDGenerator;
import kaos.ontology.jena.ActorConcepts;
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
  private Servlet _timingServlet;
  private final String _timingServletPath = "/TestMediationPerformanceServlet";


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
      ServiceBroker sb = bs.getServiceBroker();

      _log = (LoggingService) sb.getService(this,
                                            LoggingService.class,
                                            null);

      _log.info("InitNodePlugin.setupSubscriptions");

      // Construct the Enforcer

      // Registering the enforcer may lead to policies getting published
      // on the blackboard so we need to temporarily close it.
      getBlackboardService().closeTransactionDontReset();
      try {
        _servletEnf = new ServletNodeEnforcer(sb);
        _servletEnf.registerEnforcer();

        _msgEnf     = new ULMessageNodeEnforcer(sb,getAgents());
        _msgEnf.registerEnforcer();
      } catch (Throwable th) {
        _log.error("InitNodePlugin: Error registering the enforcers", th);
      } finally {
        getBlackboardService().openTransaction();
      }

      // Construct the servlet - throw away code for Ultralog
      _messageServlet = new TestMessageMediationServlet();
      _servletServlet = new TestServletMediationServlet();
      _timingServlet  = new TestMediationPerformanceServlet();

      servletService = (ServletService)
        sb.getService(this,
                      ServletService.class,
                      null);
      if (servletService == null) {
        throw new IllegalStateException("Unable to obtain ServletService");
      }
      servletService.register(_messageServletPath, _messageServlet);
      servletService.register(_servletServletPath, _servletServlet);
      servletService.register(_timingServletPath, _timingServlet);

      //      getDirService(sb);
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
        _msgEnf.testEnforcer(out);
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
      _log.info("TestServletMediation: Doing Get...");
      try {
        PrintWriter out = res.getWriter();
        out.print("<html>\n" + 
                  "<head>\n" + 
                  "<TITLE>Servlet Mediation Tests</TITLE>\n" + 
                  "</head>\n" + 
                  "<body>\n" + 
                  "<H1>Servlet Medition Check</H1>\n");
        _servletEnf.testEnforcer(out);
        out.print("\n" + 
                  "</body>\n" +
                  "</html>\n");
      } catch (UnknownConceptException e) {
        _log.error(".TestServletMediationServlet: Problem with Enforcer",
                   e);
        IOException newe = new IOException("Problem with Enforcer");
        newe.initCause(e);
        throw newe;
      }
    }

  }

  /*
   * An extremely simple servlet for some basic testing.
   */
  private class TestMediationPerformanceServlet extends HttpServlet 
  {
      
    /*
     * This function writes some initial introductory html before
     * calling the DummyNodeEnforcer for a test and some print
     * statements.  Then the function wraps up the html page.
     */
    public void doGet(HttpServletRequest req,
                      HttpServletResponse res) throws IOException 
    {
      _log.info("TestTiming: Doing Get...");
      {
        PrintWriter out = res.getWriter();
        out.print("<html>\n" + 
                  "<head>\n" + 
                  "<TITLE>Mediation Performance Tests</TITLE>\n" + 
                  "</head>\n" + 
                  "<body>\n" + 
                  "<H1>Timing Medition Routines</H1>\n");
        _msgEnf.testTiming(out);
        _servletEnf.testTiming(out);
        out.print("\n" + 
                  "</body>\n" +
                  "</html>\n");
      }
    }
  }
}
