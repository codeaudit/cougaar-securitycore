/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

import java.util.List;
import java.util.TimerTask;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Calendar;
import java.util.TimeZone;
import java.util.Enumeration;
import java.util.Collection;

import java.io.Serializable;

import edu.jhuapl.idmef.IDMEFTime;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Alert;

// Cougaar core services
import org.cougaar.core.mts.MessageAddress;

import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.community.CommunityService;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.Condition;
import org.cougaar.core.agent.ClusterIdentifier;

import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUpReply;

// Cougaar overlay
import org.cougaar.core.security.constants.IdmefClassifications;

import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.util.UnaryPredicate;

/**
 * Queries for LOGIN_FAILURE IDMEF messages and creates a LOGIN_FAILURE_RATE
 * condition from the results. The arguments to the plugin
 * component in the .ini file determine how LOGINFAILURERATEs are
 * generated.
 *
 * <table width="100%">
 * <tr><td>Parameter Number</td><td>Type</td><td>Meaning</td></tr>
 * <tr><td>1</td><td>Integer</td><td>Poll interval in seconds.
 *   Determines how often LOGIN_FAILURE_RATE is recalculated.</td></tr>
 * <tr><td>2</td><td>Integer</td><td>Window for LOGINFAILUREs to be gathered
 * over to determin the LOGIN_FAILURE_RATE. The value is a duration in 
 * seconds.</td></tr>
 * <tr><td>3</td><td>String</td><td>The society security manager name.</td></tr>
 * </table>
 * Example:
 * <pre>
 * [ Plugins ]
 * plugin = org.cougaar.core.servlet.SimpleServletComponent(org.cougaar.planning.servlet.PlanViewServlet, /tasks)
 * plugin = org.cougaar.core.security.monitorin.plugin.LoginFailureRatePlugin(20,60)
 * plugin = org.cougaar.core.security.monitoring.plugin.LoginFailureQueryPlugin(SocietySecurityManager)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 *
 * @author George Mount <gmount@nai.com>
 */
public class LoginFailureRatePlugin extends ComponentPlugin {
  final static long SECONDSPERDAY = 60 * 60 * 24;

  /** 
   * The number of seconds that the poll can be delayed before there
   * is a problem. 
   */
  private static final int OVERSIZE = 600;

  /** Logging service */
  private LoggingService _log;

  /** The number of seconds between LOGIN_FAILURE_RATE updates */
  protected int    _pollInterval    = 0;

  /** 
   * The amount of time to take into account when determining the
   * LOGIN_FAILURE_RATE
   */
  protected int    _window          = 0;

  /**
   * Buckets, one second each, containing the login failures that
   * happened within that second.
   */
  protected int    _failures[]      = null;

  /**
   * The total number of failures that happened within the window
   */
  protected int    _totalFailures   = 0;

  /**
   * The time that the service was started
   */
  protected long   _startTime       = System.currentTimeMillis();

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
                if (IdmefClassifications.LOGIN_FAILURE.equals(cs[i].getName())) {
                  return true;
                }
              }
            }
          }
        }
        return false;
      }
    };
    
  /**
   * Gets the poll interval (seconds between LOGIN_FAILURE_RATE updates)
   * and window (the number of seconds over which the LOGIN_FAILURE_RATE
   * is determined) from the recipe parameters.
   */
  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;

    String paramName = "poll interval";
    Iterator iter = l.iterator();
    String param = "";
    try {
      param = iter.next().toString();
      _pollInterval = Integer.parseInt(param);

      paramName = "window duration";
      param = iter.next().toString();
      _window = Integer.parseInt(param);
      
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
    if (_window <= 0 || _pollInterval <= 0) {
      throw new IllegalArgumentException("You must provide positive " +
                                         "window and poll interval arguments");
    }

    _failures = new int[_window + OVERSIZE];
    for (int i = 0; i < _failures.length; i++) {
      _failures[i] = 0;
    }
  }

  /**
   * Sets up the login failure rate task for
   * updating the rate at the interval specified in the configuartion
   * parameters. 
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);

    _loginFailureQuery = (IncrementalSubscription)
      getBlackboardService().subscribe(LOGIN_FAILURES_PREDICATE);

    ThreadService ts = (ThreadService) getServiceBroker().
      getService(this, ThreadService.class, null);
    ts.schedule(new LoginFailureRateTask(),
                0, ((long)_pollInterval) * 1000);
  }

  /**
   * Counts the number of LOGINFAILURE's and updates the count for
   * the current second.
   */
  public void execute() {
    if (_loginFailureQuery.hasChanged()) {
      long now = System.currentTimeMillis();

      Collection added = _loginFailureQuery.getAddedCollection();
      int count = added.size();

      synchronized (_failures) {
        _failures[(int)((now - _startTime)/1000)%_failures.length] += count;
        _totalFailures += count;
      }
    }
  }

  /**
   * A condition published to the blackboard whenever there is a 
   * login failure rate change. The target for this condition is the
   * Adaptivity Engine.
   */
  static class LoginFailureRateCondition
    implements Condition, Serializable {
    Double _rate;
    static final OMCRangeList RANGE = 
      new OMCRangeList(new Double(0.0), new Double(Integer.MAX_VALUE));
 
    public LoginFailureRateCondition() {
      setRate(-1);
    }
      
    public OMCRangeList getAllowedValues() {
      return RANGE;
    }
     
    public String getName() {
      return "org.cougaar.core.security.monitoring.LOGIN_FAILURE_RATE";
    }
  
    public Comparable getValue() {
      return _rate;
    }

    public void setRate(int rate) {
      _rate = new Double((double) rate);
    }
  }

  /**
   * This class is used internally to periodically update the 
   * login failure rate. It relies on the ThreadService to trigger
   * its run() method.
   */
  class LoginFailureRateTask extends TimerTask {
    int  _lastCleared= (OVERSIZE + (int) 
                        (_startTime - 
                         System.currentTimeMillis())/1000)%_failures.length;
    int  _prevTotal = -1;

    /**
     * The LOGIN_FAILURE_RATE that was last reported.
     */
    protected LoginFailureRateCondition _rate = null;

    public LoginFailureRateTask() {
    }

    /**
     * Counts the login failures and checks to see if the rate needs
     * to be reported to the Adaptivity Engine. It also cleans out the
     * buckets expected to be filled before the next call to run() is
     * triggered.
     */
    public void run() {
      boolean report = false;
      synchronized (_failures) {
        long now = System.currentTimeMillis();
        int  bucketOn = (int)((now - _startTime)/1000)%_failures.length;

        if (_totalFailures != _prevTotal) {
          _prevTotal = _totalFailures;
          report = true;
        }

        // clear the buckets between 
        int nextCleared = (bucketOn + _pollInterval + OVERSIZE) % 
          _failures.length;
        while (_lastCleared != nextCleared) {
          _totalFailures -= _failures[_lastCleared];
          _failures[_lastCleared] = 0;
          _lastCleared = (_lastCleared + 1) % _failures.length;
        }
      }

      if (report) {
        reportRate(_prevTotal);
      }
    }

    /**
     * Publishes a change in the login failure rate condition to the
     * blackboard.
     */
    private void reportRate(int failureCount) {
      int rate = (int) (failureCount * SECONDSPERDAY / _window);
      _log.debug("Rate = " + rate + " login failures/day");

      boolean add = false;
      if (_rate == null) {
        _rate = new LoginFailureRateCondition();
        add = true;
      }
      _rate.setRate(rate);
      getBlackboardService().openTransaction();
      if (add) {
        getBlackboardService().publishAdd(_rate);
      } else {
        getBlackboardService().publishChange(_rate);
      }
      getBlackboardService().closeTransaction();
    }
  }
}
