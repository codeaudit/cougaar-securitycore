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
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.adaptivity.OperatingModeImpl;
import org.cougaar.core.adaptivity.OMCRange;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.OMCThruRange;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.security.services.crypto.LdapUserService;
import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.security.monitoring.blackboard.Event;

import org.cougaar.lib.aggagent.query.AggregationQuery;
import org.cougaar.lib.aggagent.query.ScriptSpec;
import org.cougaar.lib.aggagent.query.QueryResultAdapter;
import org.cougaar.lib.aggagent.query.AggregationResultSet;
import org.cougaar.lib.aggagent.query.ResultSetDataAtom;

import org.cougaar.lib.aggagent.session.UpdateDelta;
import org.cougaar.lib.aggagent.session.SubscriptionAccess;
import org.cougaar.lib.aggagent.session.IncrementFormat;

import org.cougaar.lib.aggagent.util.Enum.ScriptType;
import org.cougaar.lib.aggagent.util.Enum.XmlFormat;
import org.cougaar.lib.aggagent.util.Enum.UpdateMethod;
import org.cougaar.lib.aggagent.util.Enum.Language;
import org.cougaar.lib.aggagent.util.Enum.QueryType;
import org.cougaar.lib.aggagent.util.Enum.Language;

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
import javax.naming.NamingException;

/**
 * This class queries login failures and will lockout users who
 * have failed to login too many times. The values for maximum
 * login failures and lockout duration are retrieved from
 * Operating Modes driven by the adaptivity engine.
 * Add these lines to your agent:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.UserLockoutPlugin(600,86400)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 * Here, the number 600 is the duration to wait (in seconds) between checking
 * the login failures for deletion. 86400 represents the amount of time to
 * keep the login failures before deleting it.
 */
public class UserLockoutPlugin extends ComponentPlugin {
  int  _maxFailures   = 3;
  long _cleanInterval = 1000 * 60 * 10;      // 10 minutes
  long _rememberTime  = 1000 * 60 * 60;      // 1 hour
  long _lockoutTime   = 1000 * 60 * 60 * 24; // 1 day

  FailureCache _failures       = new FailureCache();
  String _clusters[]           = null;
  private LoggingService  _log;
  private LdapUserService _userService;
  private IncrementalSubscription _maxLoginFailureSubscription;
  private IncrementalSubscription _lockoutDurationSubscription;

  private OperatingMode _maxLoginFailureOM = null;
  private OperatingMode _lockoutDurationOM = null;
  private IncrementalSubscription _queryChanged;

  private static final OMCRange []LD_VALUES = {
    new OMCThruRange(-1.0, Double.MAX_VALUE) 
  };
  private static final OMCRangeList MAX_LOGIN_FAILURE_RANGE =
      new OMCRangeList(new OMCThruRange(1.0, Double.MAX_VALUE ));
  private static final OMCRangeList LOCKOUT_DURATION_RANGE =
      new OMCRangeList(LD_VALUES);


  private static final ScriptSpec PRED_SPEC =
    new ScriptSpec(ScriptType.UNARY_PREDICATE, Language.JAVA,
                   LoginFailurePredicate.class.getName());
  private static ScriptSpec FORMAT_SPEC =
    new ScriptSpec(Language.JAVA, XmlFormat.INCREMENT, 
                   LoginFailurePredicate.class.getName());

  private static final String MAX_LOGIN_FAILURES =
    "org.cougaar.core.security.monitoring.MAX_LOGIN_FAILURES";
  private static final String LOCKOUT_DURATION =
    "org.cougaar.core.security.monitoring.LOCKOUT_DURATION";

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

    if (!iter.hasNext()) {
      throw new IllegalArgumentException("You must provide at least one " +
                                         "cluster id parameter");
    }

    ArrayList clusters = new ArrayList();
    while (iter.hasNext()) {
      clusters.add(iter.next().toString());
    }
    _clusters = (String[]) clusters.toArray(new String[clusters.size()]);
  }

  public void lock(String user) throws NamingException {
    _log.debug("locking out user (" + user + ")");
    if (_lockoutTime < 0) {
      _userService.disableUser(user);
    } else {
      _userService.disableUser(user, _lockoutTime);
    }
  }

  protected AggregationQuery createQuery() {
    AggregationQuery aq = new AggregationQuery(QueryType.PERSISTENT);
    aq.setName("Login Rate Query");
    aq.setUpdateMethod(UpdateMethod.PUSH);
    
    for (int i = 0 ; i < _clusters.length; i++) {
      aq.addSourceCluster(_clusters[i]);
    }

    aq.setPredicateSpec(PRED_SPEC);
    aq.setFormatSpec(FORMAT_SPEC);
    return aq;
  }

  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);
    _userService = (LdapUserService)
	getServiceBroker().getService(this, LdapUserService.class, null);
    AggregationQuery aq = createQuery();
    QueryResultAdapter qra = new QueryResultAdapter(aq);
    BlackboardService blackboard = getBlackboardService();
    _queryChanged = (IncrementalSubscription)
      getBlackboardService().subscribe(new QueryChanged());

    try {
      blackboard.publishAdd(qra);
    } catch (Exception e) {
      e.printStackTrace();
    }

    _maxLoginFailureSubscription = (IncrementalSubscription)blackboard.subscribe(MAX_LOGIN_FAILURE_PREDICATE);
    _lockoutDurationSubscription = (IncrementalSubscription)blackboard.subscribe(LOCKOUT_DURATION_PREDICATE);
    
    // read init values from config file and set operating modes accordingly
    _maxLoginFailureOM = new OperatingModeImpl(MAX_LOGIN_FAILURES, 
                                               MAX_LOGIN_FAILURE_RANGE, 
                                               new Double(_maxFailures));
    _lockoutDurationOM = new OperatingModeImpl(LOCKOUT_DURATION, 
                                               LOCKOUT_DURATION_RANGE, 
                                               new Double(_lockoutTime/1000));
    
    blackboard.publishAdd(_maxLoginFailureOM);
    blackboard.publishAdd(_lockoutDurationOM);
  }

  protected void execute() {
    if (_maxLoginFailureSubscription.hasChanged()) {
      updateMaxLoginFailures();
    }
    if (_lockoutDurationSubscription.hasChanged()) {
      updateLockoutDuration();
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
    } else {
      _log.error("maxLoginFailureSubscription.getChangedCollection() returned collection of size 0!");
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
    } else {
      _log.error("lockoutDurationSubscription.getChangedCollection() returned collection of size 0!");
    }
  }

  private class FailureCache extends Thread {
    HashMap _failures = new HashMap();
    
    public FailureCache() {
      setDaemon(true);
      start();
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
      while (true) {
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
        try {
          sleep(_cleanInterval);
        } catch (InterruptedException e) {
        }
      }
    }

  }

  protected static class CacheNode {
    int  failureCount = 0;
    long lastFailure;
  }

  public static class LoginFailurePredicate
    implements UnaryPredicate, IncrementFormat {

    // UnaryPredicate API
    public boolean execute(Object obj) {
      if (!(obj instanceof Event)) {
        return false;
      }
      Event event = (Event) obj;
      IDMEF_Message msg = event.getEvent();
      if (!(msg instanceof Alert)) {
        return false;
      }
      Alert alert = (Alert) msg;
      Target target[];
      if (alert.getDetectTime() == null || alert.getTargets() == null) {
        return false;
      }
      Classification[] classifications = alert.getClassifications();
      for (int i = 0; i < classifications.length; i++) {
        if (KeyRingJNDIRealm.LOGIN_FAILURE_ID.
            equals(classifications[i].getName())) {
          return true;
        }
      }
      return false;
    }

    // IncrementFormat API
    public void encode(UpdateDelta out, SubscriptionAccess sacc) {
      Collection added = sacc.getAddedCollection();
      Collection addTo = out.getAddedList();
      
      if (added == null) {
        return;
      }
      Iterator iter = added.iterator();
      while (iter.hasNext()) {
        Alert          failure   = (Alert) ((Event)iter.next()).getEvent();
        String         user      = null;
        String         reason    = null;
        Target         targets[] = failure.getTargets();
        AdditionalData addData[] = failure.getAdditionalData();

        for (int i = 0; i < targets.length && user == null; i++) {
          User u = targets[i].getUser();
          if (u != null) {
            UserId uids[] = u.getUserIds();
            if (uids != null) {
              user = uids[0].getName();
            }
          }
        }
        for (int i = 0; i < addData.length && reason == null; i++) {
          String meaning = addData[i].getMeaning();
          if (KeyRingJNDIRealm.FAILURE_REASON.equals(meaning)) {
            reason = addData[i].getAdditionalData();
          }
        }
        if (user != null && reason != null) {
          ResultSetDataAtom atom = new ResultSetDataAtom();
          atom.addIdentifier("user", user);
          atom.addValue("reason", reason);
          addTo.add(atom);
        }
      }
    }
  }

  private static class QueryChanged implements UnaryPredicate {
    public QueryChanged() {
    }

    public boolean execute(Object o) {
      return (o instanceof QueryResultAdapter);
    }
  }

}
