package org.cougaar.core.security.policy.enforcers.init;

import dummy.enforcers.ServletNodeEnforcer;
import dummy.enforcers.ULMessageNodeEnforcer;

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
  private Servlet _servlet;
  private final String _servletPath = "/TestEnforcerServlet";


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
	// There is an issue concerning how agents get associated with
	// the enforcer.  The enforcer does not know about them ahead
	// of time and they will vary as time goes on.

	_servletEnf = new ServletNodeEnforcer(sb);
	_servletEnf.registerEnforcer();

	_msgEnf     = new ULMessageNodeEnforcer(sb,getAgents());
	_msgEnf.registerEnforcer();

	// Construct the servlet - throw away code for Ultralog
	_servlet = new TestEnforcerServlet();
	servletService = (ServletService)
	    sb.getService(this,
			  ServletService.class,
			  null);
	if (servletService == null) {
	    throw new RuntimeException("Unable to obtain ServletService");
	}
	servletService.register(_servletPath, _servlet);

	//	getDirService(sb);
    } catch (Exception e) {
      e.printStackTrace();
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
  private class TestEnforcerServlet extends HttpServlet 
  {
      
      /*
       * This function writes some initial introductory html before
       * calling the DummyNodeEnforcer for a test and some print
       * statements.  Then the function wraps up the html page.
       */
      public void doGet(HttpServletRequest req,
			HttpServletResponse res) throws IOException 
      {
	  _log.info("Doing Get...");
	  try {
	      PrintWriter out = res.getWriter();
	      out.print("<html>\n" + 
			"<head>\n" + 
			"<TITLE>Test Enforcer Servlet</TITLE>\n" + 
			"</head>\n" + 
			"<body>\n" + 
			"<H1>Hello</H1>\n" + 
			"<P>Loading this page runs a test on the Enforcer</P>\n");
	      _servletEnf.testEnforcer(out);
	      _msgEnf.testEnforcer(out);
	      out.print("</P>\n" + 
			"</body>\n" +
			"</html>\n");
	  } catch (UnknownConceptException e) {
	      e.printStackTrace();
	      throw new IOException("Problem with Enforcer");
	  }
      }
  }
}
