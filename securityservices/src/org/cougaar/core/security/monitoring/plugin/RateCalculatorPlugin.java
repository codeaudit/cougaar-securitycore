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
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.idmef.ConsolidatedCapabilities;
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
 * Queries for IDMEF messages and creates a 
 * condition from the results. The arguments to the plugin
 * component in the .ini file determine how rates are
 * generated.
 *
 * <table width="100%">
 * <tr><td>Parameter Number</td><td>Type</td><td>Meaning</td></tr>
 * <tr><td>1</td><td>Integer</td><td>Poll interval in seconds.
 *   Determines how often the rate is recalculated.</td></tr>
 * <tr><td>2</td><td>Integer</td><td>Window for IDMEF messages to be gathered
 * over to determine the rate. The value is a duration in 
 * seconds.</td></tr>
 * <tr><td>3</td><td>String</td><td>The IDMEF message category to examine.</td></tr>
 * <tr><td>4</td><td>String</td><td>The name of the condition to post to the blackboard</td></tr>
 * </table>
 * Example:
 * <pre>
 * [ Plugins ]
 * plugin = org.cougaar.core.servlet.SimpleServletComponent(org.cougaar.planning.servlet.PlanViewServlet, /tasks)
 * plugin = org.cougaar.core.security.monitorin.plugin.RateCalculatorPlugin(20,60,org.cougaar.core.security.monitoring.LOGIN_FAILURE,org.cougaar.core.security.monitoring.LOGIN_FAILURE_RATE)
 * plugin = org.cougaar.core.security.monitoring.plugin.EventQueryPlugin(SocietySecurityManager,org.cougaar.core.security.monitoring.plugin.AllLoginFailures)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 *
 * @author George Mount <gmount@nai.com>
 */
public class RateCalculatorPlugin extends ComponentPlugin {
  final static long SECONDSPERDAY = 60 * 60 * 24;

  /** 
   * The number of seconds that the poll can be delayed before there
   * is a problem. 
   */
  private static final int OVERSIZE = 600;

  /** Logging service */
  private LoggingService _log;

  /** The number of seconds between rate updates */
  protected int    _pollInterval    = 0;

  /** 
   * The amount of time to take into account when determining the
   * rate.
   */
  protected int    _window          = 0;

  /**
   * Buckets, one second each, containing the count of appropriate
   * IDMEF messages that happened within that second.
   */
  protected int    _messages[]      = null;

  /**
   * The total number of IDMEF messages that happened within the window
   */
  protected int    _totalMessages   = 0;

  /**
   * The time that the service was started
   */
  protected long   _startTime       = System.currentTimeMillis();

  /**
   * Subscription to the IDMEF messages on the local blackboard
   */
  protected IncrementalSubscription _subscription;

  /**
   * The IDMEF classification to search for.
   */
  protected String _classification;

  /**
   * The condition name for this rate
   */
  protected String _conditionName;

  /**
   * The predicate indicating that we should retrieve all new
   * IDMEF messages with a given classification
   */
  private UnaryPredicate SUBSCRIPTION_PREDICATE = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof Event) {
          IDMEF_Message msg = ((Event) o).getEvent();
          if (msg instanceof RegistrationAlert ||
              msg instanceof ConsolidatedCapabilities) {
            return false;
          }
          _log.debug("GOT ALERT: " + msg);
          if (msg instanceof Alert) {
            Alert alert = (Alert) msg;
            if (alert.getAssessment() != null) {
              return false; // never look at assessment alerts
            } // end of if (alert.getAssessment() != null)
            
            Classification cs[] = alert.getClassifications();
            if (cs != null) {
              for (int i = 0; i < cs.length; i++) {
                if (_classification.equals(cs[i].getName())) {
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
   * Gets the poll interval (seconds between rate updates),
   * window (the number of seconds over which the rate
   * is determined), IDMEF classification, and condition name.
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

      paramName = "IDMEF message classification";
      _classification = iter.next().toString();
      
      paramName = "Rate condition name";
      _conditionName = iter.next().toString();
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

    _messages = new int[_window + OVERSIZE];
    for (int i = 0; i < _messages.length; i++) {
      _messages[i] = 0;
    }
  }

  /**
   * Sets up the rate task for
   * updating the rate at the interval specified in the configuartion
   * parameters. 
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);

    _subscription = (IncrementalSubscription)
      getBlackboardService().subscribe(SUBSCRIPTION_PREDICATE);

    ThreadService ts = (ThreadService) getServiceBroker().
      getService(this, ThreadService.class, null);
    ts.schedule(new RateTask(),
                0, ((long)_pollInterval) * 1000);
  }

  /**
   * Counts the number of IDMEF messages and updates the count for
   * the current second.
   */
  public void execute() {
    if (_subscription.hasChanged()) {
      long now = System.currentTimeMillis();

      Collection added = _subscription.getAddedCollection();
      int count = added.size();

      synchronized (_messages) {
        _messages[(int)((now - _startTime)/1000)%_messages.length] += count;
        _totalMessages += count;
      }
    }
  }

  /**
   * A condition published to the blackboard whenever there is a 
   * rate change. The target for this condition is the
   * Adaptivity Engine.
   */
  static class RateCondition
    implements Condition, Serializable {
    Double _rate;
    static final OMCRangeList RANGE = 
      new OMCRangeList(new Double(0.0), new Double(Integer.MAX_VALUE));
    String _name;
 
    public RateCondition(String name) {
      _name = name;
      setRate(-1);
    }
      
    public OMCRangeList getAllowedValues() {
      return RANGE;
    }
     
    public String getName() {
      return _name;
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
   * rate. It relies on the ThreadService to trigger
   * its run() method.
   */
  class RateTask extends TimerTask {
    int  _lastCleared= (OVERSIZE + (int) 
                        (_startTime - 
                         System.currentTimeMillis())/1000)%_messages.length;
    int  _prevTotal = -1;

    /**
     * The rate that was last reported.
     */
    protected RateCondition _rate = null;

    public RateTask() {
    }

    /**
     * Counts the IDMEF messages and checks to see if the rate needs
     * to be reported to the Adaptivity Engine. It also cleans out the
     * buckets expected to be filled before the next call to run() is
     * triggered.
     */
    public void run() {
      boolean report = false;
      synchronized (_messages) {
        long now = System.currentTimeMillis();
        int  bucketOn = (int)((now - _startTime)/1000)%_messages.length;

        if (_totalMessages != _prevTotal) {
          _prevTotal = _totalMessages;
          report = true;
        }

        // clear the buckets between 
        int nextCleared = (bucketOn + _pollInterval + OVERSIZE) % 
          _messages.length;
        while (_lastCleared != nextCleared) {
          _totalMessages -= _messages[_lastCleared];
          _messages[_lastCleared] = 0;
          _lastCleared = (_lastCleared + 1) % _messages.length;
        }
      }

      if (report) {
        reportRate(_prevTotal);
      }
    }

    /**
     * Publishes a change in the rate condition to the
     * blackboard.
     */
    private void reportRate(int messageCount) {
      int rate = (int) (messageCount * SECONDSPERDAY / _window);
      if (_log.isDebugEnabled()) {
        _log.debug(_conditionName + " = " + rate +
                   " " + _classification + "/day");
      } // end of if (_log.isDebugEnabled())

      boolean add = false;
      if (_rate == null) {
        _rate = new RateCondition(_conditionName);
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
