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

import org.cougaar.multicast.AttributeBasedAddress;
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
 * Base class for UserLockoutPlugin and LoginFailureRatePlugin
 * which both have the duties of querying Login Failures and updating
 * the queries with new sensor lists when more come online.
 */
public abstract class LoginFailureQueryPluginBase extends ComponentPlugin {

  /** predicate script for the aggregation query */
  private static final ScriptSpec PRED_SPEC =
    new ScriptSpec(ScriptType.UNARY_PREDICATE, Language.JAVA, 
                   AllLoginFailuresPredicate.class.getName());

  /** Aggregation query subscription */
  protected IncrementalSubscription _loginFailureQuery;

  /** Sensor list update subscription */
  protected IncrementalSubscription _sensors;

  /** 
   * Results of the subscription are only going to belong to the 
   * _queryAdapter variable.
   */
  protected QueryResultAdapter      _queryAdapter;

  /**
   * for set/get DomainService
   */
  protected DomainService  _domainService;

  /**
   * Indicates whether the sensor search query has been published or not.
   * We shouldn't publish the query until we have sensors to search!
   */
  private boolean _queryPublished = false;

  /**
   * Sensor update predicate
   */
  private static final UnaryPredicate SENSORS_PREDICATE = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof CmrRelay) {
          CmrRelay relay = (CmrRelay)o;
          if (relay.getContent() instanceof MRAgentLookUp &&
              relay.getResponse() != null) {
            return true;
          }
        }
        return false;
      }
    };

  /**
   * Used for determining if the query results have been updated.
   */
  private UnaryPredicate _loginFailurePredicate =
    new UnaryPredicate() {
      public boolean execute(Object o) {
        return (o == _queryAdapter);
//         return (o instanceof QueryResultAdapter);
      }
    };

  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService aDomainService) {
    _domainService = aDomainService;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return _domainService;
  }

  /**
   * Must return the name of the society security manager agent
   */
  protected abstract String getSocietySecurityManagerAgent();

  /**
   * creates the AggregationQuery for use in searching for login failure
   * IDMEF messages
   */
  protected AggregationQuery createQuery() {
    AggregationQuery aq = new AggregationQuery(QueryType.PERSISTENT);
    aq.setName("Login Failure Rate Query");
    aq.setUpdateMethod(UpdateMethod.PUSH);
    aq.setPredicateSpec(getPredicateScriptSpec());
    aq.setFormatSpec(getFormatScriptSpec());
    return aq;
  }
  
  /**
   * Returns the predicate spec used when querying for login failures
   * (creating the aggregation query). Expected to be overridden by
   * subclasses -- this one returns true for all login failure IDMEF
   * messages.
   */
  protected ScriptSpec getPredicateScriptSpec() {
    return PRED_SPEC;
  }

  /**
   * Should return the Aggregation Query format ScriptSpec
   */
  protected abstract ScriptSpec getFormatScriptSpec();

  /**
   * Sets up the AggregationQuery and login failure subscriptions.
   */
  protected void setupSubscriptions() {
    AggregationQuery aq = createQuery();
    _queryAdapter = new QueryResultAdapter(aq);

    _loginFailureQuery = (IncrementalSubscription)
      getBlackboardService().subscribe(_loginFailurePredicate);

    ServiceBroker        sb           = getBindingSite().getServiceBroker();
    DomainService        ds           = getDomainService(); 
    CmrFactory           cmrFactory   = (CmrFactory) ds.getFactory("cmr");
    IdmefMessageFactory  imessage     = cmrFactory.getIdmefMessageFactory();

    Classification classification = 
      imessage.createClassification("LOGINFAILURE", null);
    MRAgentLookUp lookup = new MRAgentLookUp( null, null, null, null, 
                                              classification);
    ClusterIdentifier destination = 
      new ClusterIdentifier(getSocietySecurityManagerAgent());
    CmrRelay relay = cmrFactory.newCmrRelay(lookup, destination);

    _sensors = (IncrementalSubscription) 
      getBlackboardService().subscribe(SENSORS_PREDICATE);

    getBlackboardService().publishAdd(relay);
  }

  /**
   * Called whenever there is an update in the AggregationQuery results
   * or there is a change to the sensors.
   * Updates the count of login failures for the bucket associated with
   * the current second. 
   */
  public void execute() {
    if (_loginFailureQuery.hasChanged()) {
      processLoginFailure(_queryAdapter);
    }
    if (_sensors.hasChanged()) {
      updateSensors();
    }
  }

  /**
   * Processes a new login failure
   */
  protected abstract void processLoginFailure(QueryResultAdapter queryResult);

  /**
   * Updates the Aggregation Query to use the changed sensor capabilities list
   */
  private synchronized void updateSensors() {
    Enumeration e = _sensors.getChangedList();
    AggregationQuery query = _queryAdapter.getQuery();
    while (e.hasMoreElements()) {
      CmrRelay relay = (CmrRelay) e.nextElement();
      MRAgentLookUpReply reply = (MRAgentLookUpReply) relay.getResponse();
      List agents = reply.getAgentList();
      Iterator iter = agents.iterator();
      while (iter.hasNext()) {
        String agent = iter.next().toString();
        query.addSourceCluster(agent);
      }
    }

    if (_queryPublished) {
      getBlackboardService().publishChange(_queryAdapter);
    } else {
      getBlackboardService().publishAdd(_queryAdapter);
      _queryPublished = true;
    }
  }

  /**
   * This class is used internally for the Aggregation Query predicate.
   * Much easier than using Jython when the queries
   * are static.
   */
  public static class AllLoginFailuresPredicate implements UnaryPredicate {

    /**
     * UnaryPredicate API requires this. Selects the
     * objects that we're interested in on the remote Blackboard.
     */
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
  }
}
