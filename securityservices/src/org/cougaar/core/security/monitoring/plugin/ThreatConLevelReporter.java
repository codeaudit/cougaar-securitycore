/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */
package org.cougaar.core.security.monitoring.plugin;

import org.cougaar.core.adaptivity.InterAgentOperatingMode;
import org.cougaar.core.adaptivity.InterAgentOperatingModePolicy;
import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.adaptivity.OperatingModePolicy;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.ConstraintPhrase;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.UIDService;
import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.util.UnaryPredicate;

import org.cougaar.core.security.constants.AdaptiveMnROperatingModes;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.WeakHashMap;
import java.util.Set;

/**
 * This plugin subscribes to InterAgentOperatingModePolicies that are published 
 * to the PolicyDomainManager by the AdaptivityEngine, and reports an InterAgentOperatingMode
 * to all of the agents in the security community that this component belongs.  The
 * security community is in the form of "<enclave>-SECURITY-COMM".
 */
public class ThreatConLevelReporter extends ComponentPlugin {
  
  private LoggingService _log;
  private CommunityService _cs;
  private UIDService _uid;
  private static final String[] OPERATING_MODE_VALUES = {"LOW", "HIGH"};
  private static final OMCRangeList OMRANGE = new OMCRangeList(OPERATING_MODE_VALUES);
  private OperatingMode _currentThreatCon = null;
  
  /**
   * Subscription to InterAgentOperatingModePolicy(s)
   */
  private IncrementalSubscription _subscription;  
  private WeakHashMap _omMap = new WeakHashMap();
  private String _securityComm;
  
  private final UnaryPredicate INTER_AGENT_OM_POLICY = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof OperatingModePolicy) {
            if (o instanceof InterAgentOperatingModePolicy) {
              InterAgentOperatingModePolicy iaomp =
                (InterAgentOperatingModePolicy) o;
              return iaomp.appliesToThisAgent();
            }
    	    return true;
    	  }
	      return false;
      }
    };
    
  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;
    if(l.size() != 1) {
      throw new IllegalArgumentException("Expecting one parameter " +
                                         "instead of " + l.size());
    }
    _securityComm = (String)l.iterator().next();
  }

  /**
   */
  protected void setupSubscriptions() {
    ServiceBroker sb = getServiceBroker();
    _log = (LoggingService)sb.getService(this, LoggingService.class, null);
    _cs = (CommunityService)sb.getService(this, CommunityService.class, null);
    _uid = (UIDService)sb.getService(this, UIDService.class, null);
    BlackboardService bbs = getBlackboardService();
    _subscription = (IncrementalSubscription)
      bbs.subscribe(INTER_AGENT_OM_POLICY);
    boolean debug = _log.isDebugEnabled();
    if(debug) {
      _log.debug("Security community = " + _securityComm); 
    }
    // remove the old interagent operating mode -- should be only one at most
    Collection c = bbs.query(new UnaryPredicate() { 
        public boolean execute(Object o) {
          if(o instanceof InterAgentOperatingMode) {
            OperatingMode om = (OperatingMode)o;
            return om.getName().equals(AdaptiveMnROperatingModes.THREATCON_LEVEL);
          }
          return false;
        }
      });
    Iterator iter = c.iterator();
    
    while (iter.hasNext()) {
      Object o = iter.next();
      if(debug) {
        _log.debug("removing inter agent operating mode from persistence: " + o);
      }
      bbs.publishRemove(o);
    } // end of while (iter.hasMore())
  }

  /**
   *
   */
  public void execute() {
    if (_subscription.hasChanged()) {
      // notify all the agents in a particular enclave/security community 
      removePolicies(_subscription.getRemovedCollection());
      addPolicies(_subscription.getAddedCollection());
      changePolicies(_subscription.getChangedCollection());
    }
  }
  
  private void removePolicies(Collection c) {
    Iterator i = c.iterator();
    boolean debug = _log.isDebugEnabled();
    while(i.hasNext()) {
      InterAgentOperatingModePolicy iaomp = (InterAgentOperatingModePolicy)i.next();
      //printOMPolicy(iaomp);
      InterAgentOperatingMode iaom = (InterAgentOperatingMode)_omMap.remove(iaomp);
      if(iaom != null) {
        getBlackboardService().publishRemove(iaom);
        if(debug) {
          _log.debug("removing operating mode [ " + iaom + ", " + getAgentIdentifier() + " ]"); 
        }
      }
      else {
        _log.warn("removePolicies: InterAgentOperatingMode doesn't exist for " + iaomp + " from " + iaomp.getSource());
      }
    }
  }
  
  private boolean modifyOperatingMode(InterAgentOperatingModePolicy iaomp, OperatingMode iaom) {
    boolean modified = false;
    ConstraintPhrase []constraints = iaomp.getOperatingModeConstraints();
    boolean debug = _log.isDebugEnabled();
    for(int i = constraints.length - 1; i >= 0; i--) {
      if(constraints[i].getProxyName().equals(AdaptiveMnROperatingModes.PREVENTIVE_MEASURE_POLICY)) {
        Comparable newValue = constraints[i].getValue();
        if(!iaom.getValue().equals(newValue)) {
          // no point in notifying agents if the new operating mode value is the same 
          // value as the previous/current value
          if(debug) {
            _log.debug("modifed operating mode value from " + iaom.getValue() + " to " + newValue + ".");
          }
          iaom.setValue(newValue);
          modified = true;
        } else {
          if(debug) {
          _log.debug("not modifying operating mode value since the values the same (" + newValue + ").");
          }
        }
        // doesn't make sense to constrain an operating mode more than once
        // therefore, we take the last constrain
        break;
      }
    }
    return modified;
  }
  private void changePolicies(Collection c) {
    InterAgentOperatingModePolicy iaomp = null;
    OperatingMode om = null;
    Iterator i = c.iterator();
    boolean debug = _log.isDebugEnabled();
    while(i.hasNext()) {
      iaomp = (InterAgentOperatingModePolicy)i.next();
      //printOMPolicy(iaomp);
      om = (OperatingMode)_omMap.get(iaomp);
      if(om != null && modifyOperatingMode(iaomp, om)) {
        getBlackboardService().publishChange(om);
        if(debug) {
          _log.debug("changed operating mode [ " + om + ", " + getAgentIdentifier() + " ]"); 
        }
      }
      else  {
        if(om == null) {
          _log.warn("changePolicies: InterAgentOperatingMode does not exist for " + iaomp + " from " + iaomp.getSource());
        }
      }
    }    
  }
  private InterAgentOperatingMode createThreatConMode(InterAgentOperatingModePolicy iaomp) {
    InterAgentOperatingMode iaom = null;
    boolean modified = false;
    ConstraintPhrase []constraints = iaomp.getOperatingModeConstraints();
    for(int i = constraints.length - 1; i >= 0; i--) {
      ConstraintPhrase c = constraints[i];
      String omName = c.getProxyName();
      if(omName.equals(AdaptiveMnROperatingModes.PREVENTIVE_MEASURE_POLICY)) {
        iaom = new InterAgentOperatingMode(AdaptiveMnROperatingModes.THREATCON_LEVEL, OMRANGE, c.getValue());
        iaom.setUID(_uid.nextUID());
        // doesn't make sense to constrain an operating mode more than once
        // therefore, we take the last constrain
        break;
      }
    }
    return iaom;
  }
  private void addPolicies(Collection c) {
    InterAgentOperatingModePolicy iaomp = null;
    InterAgentOperatingMode iaom = null;
    Iterator i = c.iterator();
    boolean debug = _log.isDebugEnabled();
    while(i.hasNext()) {
      iaomp = (InterAgentOperatingModePolicy)i.next();
      //printOMPolicy(iaomp);
      iaom = createThreatConMode(iaomp);
      if(iaom != null) {
        iaom.setTarget(AttributeBasedAddress.getAttributeBasedAddress(_securityComm, "Role", "Member"));
        getBlackboardService().publishAdd(iaom);  
        _omMap.put(iaomp, iaom);
        if(debug) {
          _log.debug("added operating mode [ " + iaom + ", " + getAgentIdentifier() + " ]"); 
        }
      }
    }    
  }
  
  private void printOMPolicy(OperatingModePolicy omp) {
    if(_log.isDebugEnabled()) {
      _log.debug("received operating mode policy: " + omp); 
    }
  }
}
