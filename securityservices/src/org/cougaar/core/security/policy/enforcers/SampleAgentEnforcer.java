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

import java.util.Vector;

import kaos.ontology.vocabulary.ActionConcepts;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.service.LoggingService;

import safe.enforcer.AgentEnforcer;
import safe.guard.EnforcerManagerService;

/*
 * This is the enforcer associated with an agent.  It is not yet clear
 * that we need these to do enforcement but the advantage of writing one is that
 * registering an agent enforcer ensures that the agent is registered
 * to the KAoS directory service.
 */

public class SampleAgentEnforcer
    implements AgentEnforcer
{
  private ServiceBroker _sb;
  protected LoggingService _log;
  private final String _agentName;
  // This action is a fake for now - though it seems likely that
  // there will be actions that are mediated by an enforcer that is
  // specific to an agent.
  private String _action = ActionConcepts.ActionOwlURL() + "MobilityAction";
  private Vector _agents;
  private EnforcerManagerService _guard;


  /*
   * This interface is only necessary if this is an angent
   * enforcer.  In the March demos, we will probably only use
   * NodeEnforcers and this function will not need to be written. 
   *
   * I am not really sure what this should return.  In the IHMC
   * version of this code it returns the empty string so I don't
   * think it is critical.
   */
  public String getAgentName()
  {
    return _agentName;
  }

  /*
   * This interface is only necessary if this is an angent
   * enforcer.  In the March demos, we will probably only use
   * NodeEnforcers and this function will not need to be written. 
   *
   * This function returns an identifier for the agent.  I think
   * that this function is important because it becomes the name
   * that JTP and the policy information object use to represent the
   * agent.
   */
  public String getAgentId()
  {
    return ULOntologyNames.agentPrefix + _agentName;
  }

  /*
   * Right now I return an empty vector of actions.
   */
  public Vector getControlledActionClasses()
  {
    return new Vector();
  }

  /*
   * ?
   */
  public String getName() { return "SampleAgentEnforcer"; }


  /*
   * This function initializes the SampleAgentEnforcer by providing it
   * with a service broker and the name of the agent it is covering.
   */
  public SampleAgentEnforcer(ServiceBroker sb, String agentName) {
    _agentName = agentName;
    _sb = sb;
    _agents=new Vector();
    _agents.add(ULOntologyNames.agentPrefix + _agentName);
    _log = (LoggingService) 
      _sb.getService(this, LoggingService.class, null);
  }

  /*
   * This method registers the enforcer to the guard and sets up
   * needed variables (such as the service broker and the logging
   * service). 
   *
   * This code used to be in the class 
   *   org.cougaar.core.security.policy.GuardRegistration
   * from securityservices.  I have modified the registerEnforcer
   * call a little - I need to check but I don't think that the
   * previous version works (compiles?) any longer?
   */
  public void registerEnforcer()
  {
    if (!_sb.hasService(EnforcerManagerService.class)) {
      if (_log.isWarnEnabled()) {
        _log.warn("Guard not available. Running SampleAgentEnforcer without policy");
      }
      throw new SecurityException("Guard service is not registered");
    }

    _guard = 
      (EnforcerManagerService)
      _sb.getService(this, EnforcerManagerService.class, null);
    if (_guard == null) {
      _sb.releaseService(this, EnforcerManagerService.class, _guard);
      _log.fatal("Cannot continue without guard", new Throwable());
      throw new SecurityException("Cannot continue without guard");
    }
    if (!_guard.registerEnforcer(this, _action, _agents)) {
      _sb.releaseService(this, EnforcerManagerService.class, _guard);
      _log.fatal("Could not register with the Enforcer Manager Service");
      throw new SecurityException(
                                  "Cannot register with Enforcer Manager Service");
    }
  }

}
