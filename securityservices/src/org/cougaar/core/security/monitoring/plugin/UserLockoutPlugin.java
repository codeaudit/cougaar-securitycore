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
import java.util.Enumeration;
import javax.naming.NamingException;

/**
 * This class queries login failures and will lockout users who
 * have failed to login too many times. The values for maximum
 * login failures and lockout duration are retrieved from
 * Operating Modes driven by the adaptivity engine.
 * Add these lines to your agent:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.UserLockoutPlugin(600,86400,SocietySecurityManager)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 * Here, the number 600 is the duration to wait (in seconds) between checking
 * the login failures for deletion. 86400 represents the amount of time to
 * keep the login failures before deleting it. SocietySecurityManager is
 * the agent name of the society security manager.
 */
public class UserLockoutPlugin extends LoginFailureQueryPluginBase {
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
   * The Agent name to make a request to for Login Failure sensor
   * names
   */
  protected String _socSecMgrAgent  = null;

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

  private static ScriptSpec FORMAT_SPEC =
    new ScriptSpec(Language.JAVA, XmlFormat.INCREMENT, 
                   FormatLoginFailure.class.getName());

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
      
      paramName = "society security manager agent name";
      param = iter.next().toString();
      _socSecMgrAgent = param;
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
   * Returns the society security manager agent name
   */
  protected String getSocietySecurityManagerAgent() {
    return _socSecMgrAgent;
  }

  /**
   * returns the format ScriptSpec used in the AggregationQuery
   */
  protected ScriptSpec getFormatScriptSpec() {
    return FORMAT_SPEC;
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
    
    super.setupSubscriptions();

    _userService = (LdapUserService)
	getServiceBroker().getService(this, LdapUserService.class, null);
    BlackboardService blackboard = getBlackboardService();

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
    ts.schedule(ts.getTimerTask(this, _failures),
                0, ((long)_cleanInterval) * 1000);
  }

  public void execute() {
    super.execute();
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

  /**
   * Uses Aggregation query results to update the login failure count for
   * the current user and potentially lock him out.
   */
  protected void processLoginFailure(QueryResultAdapter queryResult) {
    AggregationResultSet results = queryResult.getResultSet();
    if (results.exceptionThrown()) {
      _log.error("Exception when executing query: " + results.getExceptionSummary());
      _log.debug("XML: " + results.toXml());
    } else {
      Iterator atoms = results.getAllAtoms();
      int count = 0;
      while (atoms.hasNext()) {
        ResultSetDataAtom d = (ResultSetDataAtom) atoms.next();
        String user = d.getIdentifier("user").toString();
        String reason = d.getValue("reason").toString();
        if ("the user has entered the wrong password".equals(reason)) {
          _failures.add(user);
        }
      }
    }
  }

  private class FailureCache implements Runnable {
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

  public static class FormatLoginFailure implements IncrementFormat {
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

        if (targets == null || addData == null) {
          continue; // skip this guy
        }
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

}
