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

package org.cougaar.core.security.test.coordinator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

import java.util.*;

import org.cougaar.core.security.servlet.AbstractServletComponent;
import org.cougaar.core.security.coordinator.*;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.security.util.CommunityServiceUtilListener;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.Entity;

public class CoordinatorTest extends AbstractServletComponent {
  private String _communityName;
  private CommunityServiceUtil _csu;

  private UnaryPredicate threatconPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      return (o instanceof ThreatConAction);
    }
  };

  private UnaryPredicate compromisePredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      return (o instanceof AgentCompromiseAction);
    }
  };

  protected String getPath() {
    return "/coordinatorTest";
  }

  protected void setupSubscriptions() {
    _csu = new CommunityServiceUtil(serviceBroker);
    init();
  }

  protected void execute(HttpServletRequest request, HttpServletResponse response) {
    if (request.getMethod().equals("GET")) {
      executeGet(request, response);
    }
    else {
      executePost(request, response);
    }
  }

  protected void executeGet(HttpServletRequest request, HttpServletResponse response) {
    try {
        PrintWriter out = response.getWriter();
        out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
        out.println("<html>");
        out.println("<head>");
        out.println("<title>coordinator test </title>");
        out.println("</head>");
        out.println("<body>");
        out.println("<H2> Inject coordinator action </H2>");
        out.println("<form action=\"" + request.getRequestURI() + "\" method =\"post\">");
        out.println("Select coordinator test: <select id=\"actionName\" name=\"actionName\">");
        out.println("<option value=\"RMIAction\">Inject coordinator action to change threat level for RMI</option>");
        out.println("<option value=\"RMIPolicyAction\">Inject action to change policy to RMI only</option>");
        out.println("<option value=\"RMISSLPolicyAction\">Inject action to change policy to RMI over SSL only</option>");
        out.println("<option value=\"CompromiseAction\">Inject coordinator action to restart compromised agent</option>");

        out.println("</select><br><br>");
        out.println("Specify compromised agent: <input name=\"compromisedAgent\" type=\"text\" value=\"\"><br><br>");
        out.println("node: <input name=\"compromisedNode\" type=\"text\" value=\"\"><br><br>");
        out.println("host: <input name=\"compromisedHost\" type=\"text\" value=\"\"><br><br>");
        out.println("<br><input type=\"submit\">&nbsp;&nbsp;&nbsp;");

        out.println("<input type=\"reset\">");
        out.println("</form>");
        out.println("</body></html>");
        out.flush();
        out.close();
    } catch (Exception iox) {
        logging.error("Exception in request :" + iox);
    }
  }

  protected void executePost(HttpServletRequest request, HttpServletResponse response) {
    String msg = "Coordinator action failed to be injected: ";
    PrintWriter out;
    String action = request.getParameter("actionName");
    try {
      out = response.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      if (action.equals("RMIAction")) {
        blackboardService.openTransaction();
        Collection c = blackboardService.query(threatconPredicate);
        blackboardService.closeTransaction();
        // should be only one item
        ThreatConAction threatAction = (ThreatConAction)c.iterator().next();
        if (threatAction == null) {
          msg += "no threat con action published to blackboard.";
        }
        else {
          // what level is it now?
          Set values = threatAction.getNewPermittedValues();
          String value = (String)values.iterator().next();

          // change
          if (value.equals(ThreatConActionInfo.LOWDiagnosis)) {
            value = ThreatConActionInfo.HIGHDiagnosis;
          }
          else {
            value = ThreatConActionInfo.LOWDiagnosis;
          }
          values = new HashSet();
          values.add(value);
          threatAction.setPermittedValues(values);
          blackboardService.openTransaction();
          blackboardService.publishChange(threatAction);
          blackboardService.closeTransaction();
          msg = "RMI action initialized for threat con level: " + value;
        }
          
      } else if (action.equals("RMIPolicyAction")) {
        ThreatConActionInfo info = new ThreatConActionInfo(_communityName, ThreatConActionInfo.LOWDiagnosis);
        blackboardService.openTransaction();
        blackboardService.publishAdd(info);        
        blackboardService.closeTransaction();
        msg = "Forcing policy to switch to using RMI within enclave " + _communityName;      
      } else if (action.equals("RMISSLPolicyAction")) {
        ThreatConActionInfo info = new ThreatConActionInfo(_communityName, ThreatConActionInfo.HIGHDiagnosis);
        blackboardService.openTransaction();
        blackboardService.publishAdd(info);        
        blackboardService.closeTransaction();
        msg = "Forcing policy to switch to using RMI over SSL within enclave " + _communityName;      
      } else if (action.equals("CompromiseAction")) {
        String agent = request.getParameter("compromisedAgent");
        String node = request.getParameter("compromisedNode");
        String host = request.getParameter("compromisedHost");
        if (agent == null || agent.length() == 0) {
          msg += "no agent specified";
        }
        else {
          blackboardService.openTransaction();
          Collection c = blackboardService.query(compromisePredicate);
          blackboardService.closeTransaction();

          // should be only one item
          Iterator it = c.iterator();
          boolean found = false;
          while (it.hasNext()) {
            AgentCompromiseAction compromiseAction = (AgentCompromiseAction)it.next();
            if (!agent.equals(compromiseAction.getAssetName())) {
              continue;
            }

            found = true;
            // change
            String value = AgentCompromiseAction.RESTART;
            Set values = new HashSet();
            values.add(value);

            AgentCompromiseInfo info = new AgentCompromiseInfo(AgentCompromiseInfo.SENSOR,
              System.currentTimeMillis(), agent, node, host, AgentCompromiseInfo.SEVERE);
            compromiseAction.setCompromiseInfo(info);

            compromiseAction.setPermittedValues(values);
            blackboardService.openTransaction();
            blackboardService.publishChange(compromiseAction);
            blackboardService.closeTransaction();
            msg = "Agent compromised action initialized for agent: " + agent;
          }
          if (!found) {
            msg += "agent diagnosis does not exist " + agent;
          }
        }

      }
      else {
        msg += "invalid action " + action;
      }
      out.println(msg);
      out.println("</html>");
      out.flush();
      out.close();
    } catch (Exception iox) {
        logging.error("Exception in request :" + iox);
    }
  }

    private void init() {
      final CommunityServiceUtilListener csu = new CommunityServiceUtilListener() {
        public void getResponse(Set resp) {
          if((resp!=null)&& (!resp.isEmpty())){
            Iterator it = resp.iterator();
            Community community = (Community)it.next();
            _communityName = community.getName();

            if (logging.isDebugEnabled()) {
              logging.debug("Community updated: " + _communityName);
            }
          }
        }
      };
      _csu.getManagedSecurityCommunity(csu);
    }


}
