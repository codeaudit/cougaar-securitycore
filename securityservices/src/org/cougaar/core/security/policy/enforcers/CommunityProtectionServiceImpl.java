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
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.naming.directory.ModificationItem;

import kaos.ontology.repository.ActionInstanceDescription;
import kaos.ontology.repository.TargetInstanceDescription;
import kaos.policy.guard.KAoSSecurityException;

import org.cougaar.community.CommunityProtectionService;
import org.cougaar.community.CommunityServiceConstants;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.security.policy.ontology.UltralogActionConcepts;
import org.cougaar.core.security.policy.ontology.UltralogEntityConcepts;
import org.cougaar.core.service.LoggingService;

import safe.enforcer.NodeEnforcer;
import safe.guard.EnforcerManagerService;


public class CommunityProtectionServiceImpl
  implements CommunityProtectionService, NodeEnforcer
{
  private ServiceBroker _sb;
  private LoggingService _log;
  private EnforcerManagerService _guard;
  private static Vector _controlledActionClasses = null;
  static {
    _controlledActionClasses = new Vector();
    _controlledActionClasses.add(UltralogActionConcepts.CommunityAction);
    _controlledActionClasses.add(UltralogActionConcepts.CommunityActionSelf);
    _controlledActionClasses.add(UltralogActionConcepts.CommunityActionDelegate);
  }
  private List _agents = new Vector();

  public CommunityProtectionServiceImpl(ServiceBroker sb)
  {
    _sb = sb;
    _log = (LoggingService) _sb.getService(this, LoggingService.class, null);
    if (_log.isDebugEnabled()) {
      _log.debug("Community Protection Service constructed");
    }
  }

  public void initOwl() 
  {
    if (_guard == null) {
      registerEnforcer();
    }
  }

  public void registerEnforcer() 
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Registering Community Service Enforcer");
    }

    if (!_sb.hasService(EnforcerManagerService.class)) {
      _log.fatal("Guard service is not registered");
      throw new RuntimeException("Guard service is not registered");
    }

    _guard =
      (EnforcerManagerService)
      _sb.getService(this, EnforcerManagerService.class, null);
    if (_guard == null) {
      _log.fatal("Cannot continue without guard", new Throwable());
      throw new RuntimeException("Cannot continue without guard");
    }
    if (_log.isDebugEnabled()) {
      _log.debug("Registering with the guard");
    }
    if (!_guard.registerEnforcer(this, 
                                 UltralogActionConcepts.CommunityAction,
                                 _agents)) {
      _sb.releaseService(this, EnforcerManagerService.class, _guard);
      _log.fatal("Could not register with the Enforcer Manager Service");
      throw new RuntimeException("Cannot register with Enforcer Manager Service");
    }
  }

  /**
   * Get the name names of the Enforcer.
   *
   * @return String               Represents the enforcer name.
   */
  public String getName()
  {
    return "CommmunityServiceEnforcer";
  }

  /**
   * Get names of the action classes on which policies can be enforced.
   *
   * @return Vector              Contains strings representing ontology originated names Action classes.
  */
  public Vector getControlledActionClasses()
  {
    return _controlledActionClasses;
  }

    /**
   * Authorize request to read or modify community state.
   * @param communityName String  Name of affected community
   * @param requester String      Name of requesting agent
   * @param operation int         Requested operation (refer to
   *                         org.cougaar.core.service.CommunityServiceConstants
   *                              for valid op codes)
   * @param target String         Name of affected community member or null if
   *                              target is community
   * @param attrMods              Requested attribute modifications if request
   *                              type is MODIFY_ATTRIBUTES, ignored otherwise
   * @return boolean              Return true if request is authorized by
   *                              current policy
   */
  public boolean authorize(String             communityName,
                           String             requester,
                           int                operation,
                           String             target,
                           ModificationItem[] attrMods)
  {
    initOwl();
    if (_log.isDebugEnabled()) {
      _log.debug("" + requester + " is trying to access the community " 
                 + communityName + " using the operation " 
                 + getNameForOperation(operation)
                 + " with the target " + target);
      if (attrMods != null) {
        for (int i = 0; i < attrMods.length; i++) {
          _log.debug("attrMods[" + i + "] = " + attrMods[i]);
        }
      } else {
        _log.debug("No attribute mods");
      }
    }
    ActionInstanceDescription action = null;
    try {
      boolean delegated = !(requester.equals(target));
      Set targets = new HashSet();
      targets.add(new TargetInstanceDescription
                  (UltralogActionConcepts.communityActionType,
                   getKAoSActionType(operation)));
      if (delegated) {
        targets.add(new TargetInstanceDescription
                    (UltralogActionConcepts.communityTarget,
                     ULOntologyNames.agentPrefix + target));
      }
      targets.add(new TargetInstanceDescription
                  (UltralogActionConcepts.community,
                   ULOntologyNames.communityPrefix + communityName));
      action =
        new ActionInstanceDescription
        (delegated ? 
         UltralogActionConcepts.CommunityActionDelegate :
         UltralogActionConcepts.CommunityActionSelf,
         ULOntologyNames.agentPrefix + requester,
         targets);
      if (_log.isDebugEnabled()) {
        _log.debug("Checking permission for action " + action);
      }
      kaos.policy.guard.ActionPermission kap 
        = new kaos.policy.guard.ActionPermission("CommunityPermission", action);
      _guard.checkPermission(kap, null);
    } catch (KAoSSecurityException kse) {
      _log.warn("Permission Denied");
      _log.warn("Action = " + action);
      return false;
    } catch (Exception excp) {
      _log.warn("Unexpected Exception in policy code", excp);
      _log.warn("Operation denied: " + action);
      return false;
    }
    return true;
  }

  private static String getKAoSActionType(int op)
    throws KAoSSecurityException
  {
    switch (op) {
    case CommunityServiceConstants.JOIN:
      return UltralogEntityConcepts.JoinCommunity;
    case CommunityServiceConstants.LEAVE:
      return UltralogEntityConcepts.LeaveCommunity;
    case CommunityServiceConstants.MODIFY_ATTRIBUTES:
      return UltralogEntityConcepts.ModifyCommunityAttributes;
    case CommunityServiceConstants.GET_COMMUNITY_DESCRIPTOR:
      return UltralogEntityConcepts.GetCommunityDescriptor;
    case CommunityServiceConstants.LIST:
      return UltralogEntityConcepts.ListCommunities;
    default:
      throw new KAoSSecurityException("Unknown action type: " + op);
    }
  }

  public static String getNameForOperation(int op)
  {
    switch (op) {
    case CommunityServiceConstants.JOIN:
      return "Join";
    case CommunityServiceConstants.LEAVE:
      return "Leave";
    case CommunityServiceConstants.MODIFY_ATTRIBUTES:
      return "ModifyAttributes";
    case CommunityServiceConstants.GET_COMMUNITY_DESCRIPTOR:
      return "GetCommunityDescriptor";
    case CommunityServiceConstants.LIST:
      return "List";
    default:
      return "Unknown";
    }
  }
}
