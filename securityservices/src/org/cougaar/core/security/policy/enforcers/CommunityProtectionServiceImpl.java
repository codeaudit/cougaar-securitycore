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

package org.cougaar.core.security.policy.enforcers;

import java.util.List;
import java.util.Vector;

import javax.naming.directory.ModificationItem;

import org.cougaar.community.CommunityProtectionService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import safe.enforcer.NodeEnforcer;
import safe.guard.EnforcerManagerService;
import safe.guard.NodeGuard;


public class CommunityProtectionServiceImpl
  implements CommunityProtectionService, NodeEnforcer
{
  private ServiceBroker _sb;
  private String _enforcedActionType;
  private LoggingService _log;
  private EnforcerManagerService _guard;
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
    if (!_guard.registerEnforcer(this, _enforcedActionType, _agents)) {
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
  public Vector getControlledActionClasses ()
  {
    return new Vector();
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
    if (_log.isDebugEnabled()) {
      _log.debug("" + requester + " is trying to access the community " + communityName
                 + " using the operation " + operation + " with the target " + target);
      if (attrMods != null) {
        for (int i = 0; i < attrMods.length; i++) {
          _log.debug("attrMods[" + i + "] = " + attrMods[i]);
        }
      } else {
        _log.debug("No attribute mods");
      }
    }
    return true;
  }
}
