/**
 * Last Modified by: $Author: tredmond $
 * On: $Date: 2004-10-26 06:00:24 $
 */
package org.cougaar.core.security.test.coordinator;

import java.io.*;

import javax.servlet.*;
import javax.servlet.http.*;
import java.util.StringTokenizer;
import java.util.Collection;
import java.util.Iterator;
import java.lang.reflect.*;
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.component.*;
import org.cougaar.core.security.coordinator.ThreatConActionInfo;
import org.cougaar.core.service.*;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.planning.ldm.plan.*;


/**
 * @author James Lott
 * @version 1.0
 */
public class SetThreatConActionPlugin extends BaseServletComponent
    implements BlackboardClient
{

  public static final String DELIMITER = ":";

  protected String getPath()
  {
    return "/setThreatConAction";
  }

  public void load()
  {
    ServiceBroker sb = bindingSite.getServiceBroker();
    _log = (LoggingService) sb.getService(this,
                                          LoggingService.class,
                                          null);

    super.load();
  }

  //
  // These "setXService(XService x) {..}" methods
  // are equivalent to the SimpleServletComponent's
  // "public void load() { .. serviceBroker.getService(..); .. }"
  // calls, EXCEPT that:
  //   1) these methods are only called at load-time.
  //   2) if one of these services is not available then this
  //      Component will NOT be loaded.  In contrast, the
  //      "load()" pattern allows the Component to (optionally)
  //      continue loading even if any "getService(..)" returns null.
  //   3) these "setXService(..)" will request the service with
  //      "this" as the requestor.  The more generic "getService(..)"
  //      API allows the Component to pass a different class
  //      (e.g. an inner class to handle callbacks).
  //

  public void setBlackboardService(BlackboardService blackboard) {
    _blackboard = blackboard;
  }

  protected Servlet createServlet() {
    return new MyServlet();
  }

  private class MyServlet extends HttpServlet {
    public void doGet (HttpServletRequest request,
                       HttpServletResponse response) throws IOException
    {
      PrintWriter out = response.getWriter();
      try {
        String queryStr = request.getQueryString();
        if (queryStr == null) {
          out.println("Usage: " + getPath() + "?<OPERATING_MODE_VALUE>");
          out.println("where <OPERATING_MODE_VALUE> = LOW || HIGH");
          return;
        }
        queryStr = queryStr.toUpperCase();
        if (queryStr.equals("LOW") || queryStr.equals("HIGH")) {
          _blackboard.openTransaction();
          String level = queryStr.equals("LOW") ? 
            ThreatConActionInfo.LOWDiagnosis : 
            ThreatConActionInfo.HIGHDiagnosis;
          ThreatConActionInfo tcai = 
            new ThreatConActionInfo("Rear", level);
          _blackboard.publishAdd(tcai);
          out.println("published operating mode (value = " + queryStr + ")");
          _blackboard.closeTransactionDontReset();
        }
        else {
          out.println("Error in input: " + queryStr + " is an invalid parameter");
        }
      }
      catch (Exception ex) {
        out.print("Error: " + ex.getClass().toString());
        _log.error("Error processing request: " + request.getQueryString(),
                   ex);
      }
      out.flush();
      out.close();
    }
  }

  //
  // These are oddities of implementing BlackboardClient:
  //
  // Note: A Component must implement BlackboardClient in order
  // to obtain BlackboardService.
  //

  // odd BlackboardClient method:
  public String getBlackboardClientName() 
  {
    return toString();
  }

  // odd BlackboardClient method:
  public long currentTimeMillis() 
  {
    throw new UnsupportedOperationException(
                                            this+" asked for the current time???");
  }

  // unused BlackboardClient method:
  public boolean triggerEvent(Object event) 
  {
    // if we had Subscriptions we'd need to implement this.
    //
    // see "ComponentPlugin" for details.
    throw new UnsupportedOperationException(
                                            this+" only supports Blackboard queries, but received "+
                                            "a \"trigger\" event: "+event);
  }

  private BlackboardService _blackboard;
  private LoggingService _log;


}
