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


package org.cougaar.core.security.policy.enforcers;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;

import javax.agent.service.ServiceFailure;

import kaos.ontology.repository.ActionInstanceDescription;
import kaos.ontology.repository.TargetInstanceDescription;
import kaos.policy.guard.ActionPermission;
import kaos.policy.guard.KAoSSecurityException;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.security.policy.ontology.UltralogActionConcepts;
import org.cougaar.core.service.LoggingService;

import safe.enforcer.NodeEnforcer;
import safe.guard.EnforcerManagerService;

/**
 * This class is responsible for enforcing policy for Ultralog messages.
 */
public class WPEnforcer
    implements NodeEnforcer
{
  private ServiceBroker _sb;
  protected LoggingService _log;

  /*
   * These are going away.
   */

  public static final String WPAddAccess    = "Add";
  public static final String WPRemoveAccess = "Remove";
  public static final String WPChangeAccess = "Change";

  private EnforcerManagerService _guard;

  /**
   * This returns a list of the action classes that this controls, 
   * consisting of CommunicationActions for this enforcer.
   */
  public Vector getControlledActionClasses()
  {
    Vector result = new Vector();
    result.add(UltralogActionConcepts.WPUpdateSelf());
    result.add(UltralogActionConcepts.WPUpdateDelegate());
    result.add(UltralogActionConcepts.WPForward());
    result.add(UltralogActionConcepts.WPLookup());
    return result;
  }

  /**
   * Returns the name of the enforcer.
   */
  public String getName() { return "White Pages Enforcer"; }


  /**
   * This function initializes the ULMessageNodeEnforcer by providing it
   * with a service broker and the names of the agent it does enforcement
   * for. This agent thing is a temporary hack - it is not clear how the
   * association of agents and enforcers will take place.
   */
  public WPEnforcer(ServiceBroker sb)
  {
    _sb = sb;
    _log = (LoggingService) _sb.getService(this, LoggingService.class, null);
  }

  /**
   * This method registers the enforcer to the guard and sets up
   * needed variables (such as the service broker and the logging
   * service). 
   *
   * This code used to be in the class 
   *   org.cougaar.core.security.policy.GuardRegistration
   * from securityservices.  I have modified the registerEnforcer
   * call a little.
   */
  public void registerEnforcer() throws RuntimeException
  {
    if (!_sb.hasService(EnforcerManagerService.class)) {
      if (_log.isWarnEnabled()) {
        _log.warn("Guard not registered. WPEnforcer running without policy");
      }
      throw new RuntimeException("Guard service is not registered");
    }
    _guard = 
      (EnforcerManagerService)
      _sb.getService(this, EnforcerManagerService.class, null);
    if (_guard == null) {
      _log.fatal("Cannot continue without guard", new Throwable());
      throw new RuntimeException("Cannot continue without guard");
    }
    for (Iterator ActionTypeIt = getControlledActionClasses().iterator();
         ActionTypeIt.hasNext();) {
      String actionType = (String) ActionTypeIt.next();
      if (!_guard.registerEnforcer(this, actionType, new Vector())) {
        _sb.releaseService(this, EnforcerManagerService.class, _guard);
        _log.fatal("Could not register with the Enforcer Manager Service");
        throw new RuntimeException("Cannot register with Enforcer Manager Service");
      }
    }
  }


  /**
   * This function determines if an action is authorized.  
   *
   * @param agent - a String representing the agent making the call
   *
   * @param agentEntry - a String representing the agent whose entry is being
   *   added to the white pages
   * 
   * @param action - a String representing the action on the wp.
   */
  public boolean isActionAuthorized(String agent,
                                    String agentEntry,
                                    String action)
  {
    return true;
  }

  public boolean WPUpdateOk(String performingAgent,
                            String actedOnAgent)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Called WPUpdateOk for " + performingAgent + " and " + actedOnAgent);
    }
    String actionType = null;
    Set targets = new HashSet();
    if (performingAgent == actedOnAgent) {
      actionType = UltralogActionConcepts.WPUpdateSelf();
    } else {
      actionType = UltralogActionConcepts.WPUpdateDelegate();
      targets.add(new TargetInstanceDescription(
                           UltralogActionConcepts.wpAgentEntry(),
                           ULOntologyNames.agentPrefix + actedOnAgent));
    }
    ActionInstanceDescription aid = 
      new ActionInstanceDescription(actionType, 
                                    ULOntologyNames.agentPrefix + performingAgent,
                                    targets);
    return isActionAuthorized("White pages update", aid);
  }


  public boolean WPForwardOk(String forwardingAgent,
                             String forwardedAgent)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Called WPForwardOk for " + forwardingAgent + 
                 " and " + forwardedAgent);
    }
    Set targets = new HashSet();
    targets.add(new TargetInstanceDescription(
                           UltralogActionConcepts.WPForward(),
                           ULOntologyNames.agentPrefix + forwardedAgent));
    ActionInstanceDescription aid = 
      new ActionInstanceDescription(UltralogActionConcepts.WPForward(),
                                    ULOntologyNames.agentPrefix + forwardingAgent,
                                    targets);
    return isActionAuthorized("White pages forward", aid);
  }


  public boolean WPLookupOk(String agent)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Called WPLookupOk for " + agent);
    }
    Set targets = new HashSet();
    ActionInstanceDescription aid = 
      new ActionInstanceDescription(UltralogActionConcepts.WPLookup(),
                                    ULOntologyNames.agentPrefix + agent,
                                    targets);
    return isActionAuthorized("White Pages Lookup Action", aid);
  }

  private boolean isActionAuthorized(String desc, 
                                      ActionInstanceDescription aid)
  {
    ActionPermission ap = new ActionPermission(desc, aid);
    try {
      _guard.checkPermission(ap, null);
      return true;
    } catch (ServiceFailure sf) {
      _log.error("Something is broken so permission is denied for action "
                        + aid);
      _log.error("Guard error = " + sf);
      return false;
    } catch (KAoSSecurityException sec) {
      if (_log.isWarnEnabled()) {
        _log.warn("Permission denied for action " + aid);
      }
      return false;
    }
  }
}
