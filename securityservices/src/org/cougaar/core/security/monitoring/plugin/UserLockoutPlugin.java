/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
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
package org.cougaar.core.security.monitoring.plugin;

import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.adaptivity.OperatingModeImpl;
import org.cougaar.core.adaptivity.OMCRange;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.OMCThruRange;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.security.services.crypto.LdapUserService;
import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUpReply;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;

import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.User;
import edu.jhuapl.idmef.UserId;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.NoSuchElementException;
import java.util.TimerTask;
import java.util.Enumeration;
import javax.naming.NamingException;

/**
 * This class queries login failures and will lockout users who
 * have failed to login too many times. The values for maximum
 * login failures and lockout duration are retrieved from
 * Operating Modes driven by the adaptivity engine.
 * Add these lines to your agent:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.UserLockoutPlugin(600,86400)
 * plugin = org.cougaar.core.security.monitoring.plugin.LoginFailureQueryPlugin(SocietySecurityManager)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 * Here, the number 600 is the duration to wait (in seconds) between checking
 * the login failures for deletion. 86400 represents the amount of time to
 * keep the login failures before deleting it. SocietySecurityManager is
 * the agent name of the society security manager.
 */
public class UserLockoutPlugin extends ComponentPlugin {
  int  _maxFailures   = 3;
  long _cleanInterval = 1000 * 60 * 10;      // 10 minutes
  long _rememberTime  = 1000 * 60 * 60;      // 1 hour
  long _lockoutTime   = 1000 * 60 * 60 * 24; // 1 day

  FailureCache _failures       = new FailureCache();
  private LoggingService  _log;
  private LdapUserService _userService;
  private IncrementalSubscription _maxLoginFailureSubscription;
  private IncrementalSubscription _lockoutDurationSubscription;

  private OperatingMode _maxLoginFailureOM = null;
  private OperatingMode _lockoutDurationOM = null;

  /**
   * Subscription to the login failures on the local blackboard
   */
  protected IncrementalSubscription _loginFailureQuery;

  /**
   * The predicate indicating that we should retrieve all new
   * login failures
   */
  private static final UnaryPredicate LOGIN_FAILURES_PREDICATE = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof Event) {
          IDMEF_Message msg = ((Event) o).getEvent();
          if (msg instanceof Alert) {
            Alert alert = (Alert) msg;
            Classification cs[] = alert.getClassifications();
            if (cs != null) {
              for (int i = 0; i < cs.length; i++) {
                if (KeyRingJNDIRealm.LOGIN_FAILURE_ID.equals(cs[i].getName())) {
                  AdditionalData ad[] = alert.getAdditionalData();
                  if (ad != null) {
                    for (int j = 0; j < ad.length; j++) {
                      if (KeyRingJNDIRealm.FAILURE_REASON.equals(ad[j].getMeaning())) {
                        return ("the user has entered the wrong password".equals(ad[j].getAdditionalData()));
                      }
                    }
                  }
                  return false;
                }
              }
            }
          }
        }
        return false;
      }
    };
    
  /**
   * For OperatingModes value range
   */
  private static final OMCRange []LD_VALUES = {
    new OMCThruRange(-1.0, Double.MAX_VALUE) 
  };

  /**
   * Max login failure operating mode range
   */
  private static final OMCRangeList MAX_LOGIN_FAILURE_RANGE =
      new OMCRangeList(new OMCThruRange(1.0, Double.MAX_VALUE ));

  /**
   * Lockout duration operating mode range
   */
  private static final OMCRangeList LOCKOUT_DURATION_RANGE =
      new OMCRangeList(LD_VALUES);

  private static final String MAX_LOGIN_FAILURES =
    "org.cougaar.core.security.monitoring.MAX_LOGIN_FAILURES";
  private static final String LOCKOUT_DURATION =
    "org.cougaar.core.security.monitoring.LOCKOUT_DURATION";

  /**
   * For the max login failure OperatingMode
   */
  private static final UnaryPredicate MAX_LOGIN_FAILURE_PREDICATE =
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof OperatingMode) {
          OperatingMode om = (OperatingMode) o;
          String omName = om.getName();
          if (MAX_LOGIN_FAILURES.equals(omName)) {
            return true;
          }
        }
        return false;
      }
    };

  /**
   * For the lockout duration OperatingMode
   */
  private static final UnaryPredicate LOCKOUT_DURATION_PREDICATE = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof OperatingMode) {
          OperatingMode om = (OperatingMode) o;
          String omName = om.getName();
          if (LOCKOUT_DURATION.equals(omName)) {
          return true;
          }
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

    String paramName = "clean interval";
    Iterator iter = l.iterator();
    String param = "";
    try {
      param = iter.next().toString();
      _cleanInterval = Long.parseLong(param) * 1000;

      paramName = "failure memory";
      param = iter.next().toString();
      _rememberTime = Long.parseLong(param) * 1000;
    } catch (NoSuchElementException e) {
      throw new IllegalArgumentException("You must provide a " +
                                        paramName +
                                        " argument");
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("Expecting integer for " +
                                         paramName +
                                         ". Got (" +
                                         param + ")");
    }
    if (_cleanInterval <= 0 || _rememberTime <= 0) {
      throw new IllegalArgumentException("You must provide positive " +
                                         "clean interval and failure memory " +
                                         "arguments");
    }
  }

  /**
   * Lockout a given user for the lockout duration
   */
  public void lock(String user) throws NamingException {
    _log.debug("locking out user (" + user + ")");
    if (_lockoutTime < 0) {
      _userService.disableUser(user);
    } else {
      _userService.disableUser(user, _lockoutTime);
    }
  }

  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);
    
    _userService = (LdapUserService)
	getServiceBroker().getService(this, LdapUserService.class, null);
    BlackboardService blackboard = getBlackboardService();

    _loginFailureQuery = (IncrementalSubscription)
      blackboard.subscribe(LOGIN_FAILURES_PREDICATE);
    _maxLoginFailureSubscription = (IncrementalSubscription)
      blackboard.subscribe(MAX_LOGIN_FAILURE_PREDICATE);
    _lockoutDurationSubscription = (IncrementalSubscription)
      blackboard.subscribe(LOCKOUT_DURATION_PREDICATE);
    
    // read init values from config file and set operating modes accordingly
    _maxLoginFailureOM = new OperatingModeImpl(MAX_LOGIN_FAILURES, 
                                               MAX_LOGIN_FAILURE_RANGE, 
                                               new Double(_maxFailures));
    _lockoutDurationOM = new OperatingModeImpl(LOCKOUT_DURATION, 
                                               LOCKOUT_DURATION_RANGE, 
                                               new Double(_lockoutTime/1000));
    
    blackboard.publishAdd(_maxLoginFailureOM);
    blackboard.publishAdd(_lockoutDurationOM);

    ThreadService ts = (ThreadService) getServiceBroker().
      getService(this, ThreadService.class, null);
    ts.schedule(_failures,
                0, ((long)_cleanInterval) * 1000);
  }

  public void execute() {
    if (_maxLoginFailureSubscription.hasChanged()) {
      updateMaxLoginFailures();
    }
    if (_lockoutDurationSubscription.hasChanged()) {
      updateLockoutDuration();
    }
    if (_loginFailureQuery.hasChanged()) {
      processLoginFailure();
    }
  }

  private void updateMaxLoginFailures() {
    Collection oms = _maxLoginFailureSubscription.getChangedCollection();
    Iterator i = oms.iterator();
    OperatingMode om = null;
    if (oms.size() > 0) {
      om = (OperatingMode)i.next();
      _log.debug("Max Login Failures updated to " + om.getValue() + ".");
      _maxFailures = (int) Double.parseDouble(om.getValue().toString());
    }
  }

  private void updateLockoutDuration() {
    Collection oms = _lockoutDurationSubscription.getChangedCollection();
    Iterator i = oms.iterator();
    OperatingMode om = null;
    if (oms.size() > 0) {
      om = (OperatingMode)i.next();
      _log.debug("Lockout Duration updated to " + om.getValue() + " seconds.");
      _lockoutTime = (long)Double.parseDouble(om.getValue().toString()) * 1000;
    }
  }

  /**
   * Process a new login failure IDMEF event.
   */
  private void processLoginFailure() {
    Enumeration iter = _loginFailureQuery.getAddedList();

    while (iter.hasMoreElements()) {
      Event e = (Event) iter.nextElement();
      Alert alert = (Alert) e.getEvent();
      Target ts[] = alert.getTargets();
      for (int i = 0; i < ts.length; i++) {
        User user = ts[i].getUser();
        if (user != null) {
          UserId uids[] = user.getUserIds();
          if (uids != null) {
            for (int j = 0 ; j < uids.length; j++) {
              _failures.add(uids[j].getName());
            }
          }
        }
      }
    }
  }

  private class FailureCache extends TimerTask {
    HashMap _failures = new HashMap();
    
    public FailureCache() {
    }

    public void add(String user) {
      boolean lockUser = false;
      CacheNode failure = null;
      synchronized (_failures) {
        failure = (CacheNode) _failures.get(user);
        if (failure == null) {
          failure = new CacheNode();
          _failures.put(user, failure);
        }
        failure.failureCount++;
        if (failure.failureCount >= _maxFailures) {
          _failures.remove(user);
          lockUser = true;
        }
        failure.lastFailure = System.currentTimeMillis();
      }
      if (lockUser) {
        try {
          lock(user);
        } catch (NamingException e) {
          _log.error("Could not lock user " + user + ": " + e.getMessage());
          synchronized (_failures) {
            _failures.put(user, failure); // put it back in...
          }
        }
      }
    }

    public void run() {
      long deleteTime = System.currentTimeMillis() - _rememberTime;
      synchronized (_failures) {
        Iterator iter = _failures.entrySet().iterator();
        while (iter.hasNext()) {
          Map.Entry entry = (Map.Entry) iter.next();
          CacheNode failure = (CacheNode) entry.getValue();
          if (failure.lastFailure < deleteTime) {
            iter.remove();
          }
        }
      }
    }
  }

  protected static class CacheNode {
    int  failureCount = 0;
    long lastFailure;
  }
}
