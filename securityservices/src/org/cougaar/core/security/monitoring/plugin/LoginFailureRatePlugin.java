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

import edu.jhuapl.idmef.IDMEFTime;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.lib.aggagent.query.Alert;
import org.cougaar.lib.aggagent.query.AlertDescriptor;
import org.cougaar.lib.aggagent.query.AggregationQuery;
import org.cougaar.lib.aggagent.query.QueryResultAdapter;
import org.cougaar.lib.aggagent.query.ResultSetDataAtom;
import org.cougaar.lib.aggagent.query.ScriptSpec;
import org.cougaar.lib.aggagent.query.AggregationResultSet;

import org.cougaar.lib.aggagent.session.SessionManager;
import org.cougaar.lib.aggagent.util.Enum.QueryType;
import org.cougaar.lib.aggagent.util.Enum.Language;
import org.cougaar.lib.aggagent.util.Enum.AggType;
import org.cougaar.lib.aggagent.util.Enum.ScriptType;
import org.cougaar.lib.aggagent.util.Enum.UpdateMethod;
import org.cougaar.lib.aggagent.util.Enum.XmlFormat;

import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.Condition;


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
 * <tr><td>3+</td><td>String</td><td>Cluster identifiers to scan for
 * login failures</td></tr>
 * </table>
 * Example:
 * <pre>
 * [ Plugins ]
 * plugin = org.cougaar.core.servlet.SimpleServletComponent(org.cougaar.planning.servlet.PlanViewServlet, /tasks)
 * plugin = org.cougaar.core.security.monitor.plugin.LoginFailureRatePlugin(20,60,TestNode)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 *
 * @author George Mount <gmount@nai.com>
 */
public class LoginFailureRatePlugin extends ComponentPlugin {
  static long SECONDSPERDAY = 60 * 60 * 24;
  private static final String[] STR_ARRAY = new String[1];
  private static final String PRED_SCRIPT = 
    "from edu.jhuapl.idmef import Alert\n" +
    "from org.cougaar.core.security.monitoring.blackboard import Event\n" +
    "def getAlert(x):\n" +
    "  if isinstance(x, Event) == 0:\n" +
    "    return 0\n" +
    "  event = x.getEvent()\n" +
    "  if isinstance(event, Alert) == 0:\n" +
    "    return 0\n" +
    "  for capability in event.getClassifications():\n" +
    "    if 'LOGINFAILURE' == capability.getName():\n" +
    "      detectTime = event.getDetectTime()\n" +
    "      if detectTime is None:\n" +
    "        return 0\n" +
    "      return 1\n" +
    "  return 0\n" +
    "def instantiate ():\n" +
    "  return getAlert\n";

  private static final String FORMAT_SCRIPT =
    "from org.cougaar.lib.aggagent.query import ResultSetDataAtom\n" +
    "def encode (x, out):\n" +
    "  atom = ResultSetDataAtom()\n" +
    "  atom.addIdentifier('document', x.getUID())\n" +
    "  atom.addValue('date', x.getEvent().getDetectTime().getidmefDate())\n" +
    "  out.add(atom) \n" +
    "def instantiate ():\n" +
    "  return encode\n";

  private static final ScriptSpec PRED_SPEC =
    new ScriptSpec(ScriptType.UNARY_PREDICATE, Language.JPYTHON, PRED_SCRIPT);
  private static final ScriptSpec FORMAT_SPEC =
    new ScriptSpec(Language.JPYTHON, XmlFormat.XMLENCODER, FORMAT_SCRIPT);

  private static final int OVERSIZE = 60;
  private LoggingService log;

  protected int    _pollInterval    = 0;
  protected int    _window          = 0;
  protected String _clusters[]      = null;
  protected Alert  _alert           = null;

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
    _clusters = (String[]) clusters.toArray(STR_ARRAY);
    /*
    _loginFailures = new int[_window + OVERSIZE];
    for (int i = 0; i < _loginFailures.length; i++) {
      _loginFailures[i] = 0;
    }
    */
  }

  protected AggregationQuery createQuery() {
    AggregationQuery aq = new AggregationQuery(QueryType.PERSISTENT);
    aq.setName("Login Rate Query");
    aq.setUpdateMethod(UpdateMethod.PULL);
    aq.setPullRate(_pollInterval);
    
    for (int i = 0 ; i < _clusters.length; i++) {
      aq.addSourceCluster(_clusters[i]);
    }

    aq.setPredicateSpec(PRED_SPEC);
    aq.setFormatSpec(FORMAT_SPEC);
    return aq;
  }

  protected void setupSubscriptions() {
    log = (LoggingService)
	getBindingSite().getServiceBroker().getService(this,
	LoggingService.class, null);

//     _startTime = System.currentTimeMillis();
    AggregationQuery aq = createQuery();
    QueryResultAdapter qra = new QueryResultAdapter(aq);
    _alert = new LoginFailureAlert();
    _alert.setQueryAdapter(qra);
    qra.addAlert(_alert);
//     _pollThread = new PollThread();
//     _pollThread.start();
//     getBlackboardService().openTransaction();
    try {
      getBlackboardService().publishAdd(qra);
    } catch (Exception e) {
      e.printStackTrace();
    }
//     getBlackboardService().closeTransaction();
  }

  protected void execute() {
  }
  
  private class LoginFailureAlert extends Alert {

    int _lastRate = -1;

    public LoginFailureAlert() {
      setName("LoginFailureAlert");
    }

    public void handleUpdate() {
      long now = System.currentTimeMillis();
      TimeZone gmt = TimeZone.getTimeZone("GMT");
      Calendar backTime = Calendar.getInstance(gmt);
      backTime.add(Calendar.SECOND, -_window);
      String backString = IDMEFTime.convertToIDMEFFormat(backTime.getTime());

      QueryResultAdapter qra = getQueryAdapter();
      AggregationResultSet results = qra.getResultSet();
//       log.debug("Exception thrown:  " + results.exceptionThrown());
//       log.debug("Exception Summary: " + results.getExceptionSummary());
//       log.debug("XML: " + results.toXml());
      
      Iterator atoms = results.getAllAtoms();
      int count = 0;
      while (atoms.hasNext()) {
        ResultSetDataAtom d = (ResultSetDataAtom) atoms.next();
        String val = d.getValue("date").toString();
        if (val != null && backString.compareTo(val) <= 0) {
          count++;
        }
      }
      long rate = count * SECONDSPERDAY / _window;
      log.debug("Rate = " + rate + " login failures/day");
      if (_lastRate != rate) {
        _lastRate = (int) rate;
        Condition cond = new LoginFailureRateCondition(_lastRate);
        boolean close = true;
        try {
          close = getBlackboardService().tryOpenTransaction();
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

  private static class LoginFailureRateCondition implements Condition {
    Integer _rate;
    static final OMCRangeList RANGE = 
      new OMCRangeList(new Integer(0), new Integer(Integer.MAX_VALUE));

    public LoginFailureRateCondition(int rate) {
      _rate = new Integer(rate);
    }
    
    public OMCRangeList getAllowedValues() {
      return RANGE;
    }
    
    public String getName() {
      return "LOGIN_FAILURE_RATE";
    }

    public Comparable getValue() {
      return _rate;
    }
  }
}
