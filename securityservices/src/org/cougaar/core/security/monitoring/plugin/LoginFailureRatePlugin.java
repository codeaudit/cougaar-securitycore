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
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.Condition;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.service.ThreadService;

import org.cougaar.util.UnaryPredicate;

import org.cougaar.lib.aggagent.query.AlertDescriptor;
import org.cougaar.lib.aggagent.query.AggregationQuery;
import org.cougaar.lib.aggagent.query.QueryResultAdapter;
import org.cougaar.lib.aggagent.query.ResultSetDataAtom;
import org.cougaar.lib.aggagent.query.ScriptSpec;
import org.cougaar.lib.aggagent.query.AggregationResultSet;

import org.cougaar.lib.aggagent.session.UpdateDelta;
import org.cougaar.lib.aggagent.session.SessionManager;
import org.cougaar.lib.aggagent.session.XMLEncoder;
import org.cougaar.lib.aggagent.session.SubscriptionAccess;
import org.cougaar.lib.aggagent.session.IncrementFormat;

import org.cougaar.lib.aggagent.util.Enum.QueryType;
import org.cougaar.lib.aggagent.util.Enum.Language;
import org.cougaar.lib.aggagent.util.Enum.AggType;
import org.cougaar.lib.aggagent.util.Enum.ScriptType;
import org.cougaar.lib.aggagent.util.Enum.UpdateMethod;
import org.cougaar.lib.aggagent.util.Enum.XmlFormat;

/**
 * Queries for LOGINFAILURE IDMEF messages and creates a LOGIN_FAILURE_RATE
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
 * </table>
 * Example:
 * <pre>
 * [ Plugins ]
 * plugin = org.cougaar.core.servlet.SimpleServletComponent(org.cougaar.planning.servlet.PlanViewServlet, /tasks)
 * plugin = org.cougaar.core.security.monitorin.plugin.LoginFailureRatePlugin(20,60,TestNode)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 *
 * @author George Mount <gmount@nai.com>
 */
public class LoginFailureRatePlugin extends ComponentPlugin {
  static long SECONDSPERDAY = 60 * 60 * 24;
  private static final ScriptSpec PRED_SPEC =
    new ScriptSpec(ScriptType.UNARY_PREDICATE, Language.JAVA, 
                   LoginFailurePredicate.class.getName());

  private static final ScriptSpec FORMAT_SPEC =
    new ScriptSpec(Language.JAVA,  XmlFormat.INCREMENT,
                   LoginFailurePredicate.class.getName());

  private static final int OVERSIZE = 600;
  private LoggingService log;

  private IncrementalSubscription _queryChanged;
  private QueryResultAdapter      _queryAdapter;

  protected int    _pollInterval    = 0;
  protected int    _window          = 0;
  protected String _clusters[]      = null;
  protected int    _failures[]      = null;
  protected int    _totalFailures   = 0;
  protected long   _startTime       = System.currentTimeMillis();
  protected int    _lastRate        = -1;

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
    if (!iter.hasNext()) {
      throw new IllegalArgumentException("You must provide at least one " +
                                         "cluster id parameter");
    }
    ArrayList clusters = new ArrayList();
    while (iter.hasNext()) {
      clusters.add(iter.next().toString());
    }
    _clusters = (String[]) clusters.toArray(new String[clusters.size()]);

    _failures = new int[_window + OVERSIZE];
    for (int i = 0; i < _failures.length; i++) {
      _failures[i] = 0;
    }
  }

  protected AggregationQuery createQuery() {
    AggregationQuery aq = new AggregationQuery(QueryType.PERSISTENT);
    aq.setName("Login Failure Rate Query");
    aq.setUpdateMethod(UpdateMethod.PUSH);
    
    for (int i = 0 ; i < _clusters.length; i++) {
      aq.addSourceCluster(_clusters[i]);
    }

    aq.setPredicateSpec(PRED_SPEC);
    aq.setFormatSpec(FORMAT_SPEC);
    return aq;
  }

  protected void setupSubscriptions() {
    log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);
    AggregationQuery aq = createQuery();
    _queryAdapter = new QueryResultAdapter(aq);

    _queryChanged = (IncrementalSubscription)
      getBlackboardService().subscribe(new QueryChanged());

    getBlackboardService().publishAdd(_queryAdapter);

    ThreadService ts = (ThreadService) getServiceBroker().
      getService(this, ThreadService.class, null);
    ts.schedule(ts.getTimerTask(this, new LoginFailureRateTask()),
                0, ((long)_pollInterval) * 1000);
  }

  protected void execute() {
    
    long now = System.currentTimeMillis();
    
    Enumeration e = _queryChanged.getChangedList();
    QueryResultAdapter qra = null;

    while (e.hasMoreElements() && qra == null) {
      qra = (QueryResultAdapter) e.nextElement();
      if (!qra.checkID(_queryAdapter.getID())) qra = null;
    }

    if (qra == null) return;
    AggregationResultSet results = qra.getResultSet();
    if (results.exceptionThrown()) {
      log.error("Exception when executing query: " + results.getExceptionSummary());
      log.debug("XML: " + results.toXml());
    } else {
      Iterator atoms = results.getAllAtoms();
      int count = 0;
      while (atoms.hasNext()) {
        ResultSetDataAtom d = (ResultSetDataAtom) atoms.next();
        count += Integer.parseInt(d.getValue("delta").toString());
      }
      synchronized (_failures) {
        _failures[(int)((now - _startTime)/1000)%_failures.length] += count;
        _totalFailures += count;
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

  private static class LoginFailureRateCondition
    implements Condition, Serializable {
    Double _rate;
    static final OMCRangeList RANGE = 
      new OMCRangeList(new Double(0.0), new Double(Integer.MAX_VALUE));
 
    public LoginFailureRateCondition(int rate) {
      _rate = new Double((double) rate);
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
      if (alert.getDetectTime() == null) {
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
      ResultSetDataAtom atom = new ResultSetDataAtom();
      atom.addIdentifier("LoginFailureCount", "Results");
      atom.addValue("delta", String.valueOf(sacc.getAddedCollection().size()));
      out.getAddedList().add(atom);
    }
  }

  private class LoginFailureRateTask implements Runnable {
    int  _lastCleared= (OVERSIZE + (int) 
                        (_startTime - 
                         System.currentTimeMillis())/1000)%_failures.length;
    int  _prevTotal = -1;

    public LoginFailureRateTask() {
    }
    
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

    private void reportRate(int failureCount) {
      int rate = (int) (failureCount * SECONDSPERDAY / _window);
      log.debug("Rate = " + rate + " login failures/day");
      Condition cond = new LoginFailureRateCondition(rate);
      boolean close = true;
      try {
        getBlackboardService().openTransaction();
      } catch (Exception e) {
        close = false;
      }
      try {
        getBlackboardService().publishAdd(cond);
      } catch (Exception e) {
      }
      try {
        if (close) {
          getBlackboardService().closeTransaction();
        }
      } catch (Exception e) {
      }
    }
  }
}
