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
import java.util.HashSet;

import java.io.Serializable;
import java.io.StringReader;
import java.io.IOException;

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

import org.cougaar.core.util.UID;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.Condition;
import org.cougaar.core.agent.ClusterIdentifier;

import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUpReply;
import org.cougaar.core.security.monitoring.blackboard.EventImpl;

import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.ConfigFinder;

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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.w3c.dom.Document;



/**
 * This class queries for LOGINFAILURE IDMEF messages and keeps
 * an updated list of Senors with the capability. All query results
 * are placed on the blackboard. Use this plugin with the
 * LoginFailureRatePlugin and UserLockoutPlugin. Use the following
 * in your .ini file:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.LoginFailureQueryPlugin(SocietySecurityManager)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 * SocietySecurityManager is the name of the Society Security Manager agent.
 */
public class LoginFailureQueryPlugin extends ComponentPlugin {

  private LoggingService  _log;

  /** the current agent's name */
  private String _agentName;

  /** predicate script for the aggregation query */
  private static final ScriptSpec PRED_SPEC =
    new ScriptSpec(ScriptType.UNARY_PREDICATE, Language.JAVA, 
                   AllLoginFailuresPredicate.class.getName());

  /** format script for the aggregation query */
  private static final ScriptSpec FORMAT_SPEC =
    new ScriptSpec(Language.JAVA, XmlFormat.INCREMENT, 
                   FormatLoginFailure.class.getName());

  /** Aggregation query subscription */
  protected IncrementalSubscription _loginFailureQuery;

  /** Sensor list update subscription */
  protected IncrementalSubscription _sensors;

  /** 
   * Results of the subscription are only going to belong to the 
   * a member of the _queryAdapters variable.
   */
  protected HashSet         _queryAdapters = new HashSet();

  /**
   * A set of agents that have Login Failure sensor capabilities.
   */
  protected HashSet         _agents = new HashSet();

  /**
   * for set/get DomainService
   */
  protected DomainService  _domainService;

  /**
   * Society security manager agent. Default to "SocietySecurityManager".
   * This value can be set in the parameter.
   */
  private String _societySecurityManager = "SocietySecurityManager";

  /**
   * For parsing Alert events
   */
  private DocumentBuilderFactory _parserFactory = 
    DocumentBuilderFactory.newInstance();

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
        synchronized (_queryAdapters) {
          return (_queryAdapters.contains(o));
        }
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
   * creates the AggregationQuery for use in searching for login failure
   * IDMEF messages
   */
  protected QueryResultAdapter createQuery() {
    AggregationQuery aq = new AggregationQuery(QueryType.PERSISTENT);
    aq.setName("Login Failure Rate Query");
    aq.setUpdateMethod(UpdateMethod.PUSH);
    aq.setPredicateSpec(PRED_SPEC);
    aq.setFormatSpec(FORMAT_SPEC);
    return new QueryResultAdapter(aq);
  }
  
  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;

    if (l.size() >= 1) {
      _societySecurityManager = (String) l.get(0);
      if (_log == null && getServiceBroker() != null) {
        _log = (LoggingService)
          getServiceBroker().getService(this, LoggingService.class, null);
      }
      if (_log != null) {
        _log.info("Setting security manager agent name to " + _societySecurityManager);
      }
    }
  }

  /**
   * Sets up the AggregationQuery and login failure subscriptions.
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);
    
    _loginFailureQuery = (IncrementalSubscription)
      getBlackboardService().subscribe(_loginFailurePredicate);

    ServiceBroker        sb           = getBindingSite().getServiceBroker();
    DomainService        ds           = getDomainService(); 
    CmrFactory           cmrFactory   = (CmrFactory) ds.getFactory("cmr");
    IdmefMessageFactory  imessage     = cmrFactory.getIdmefMessageFactory();
    _agentName = ((AgentIdentificationService)
                  sb.getService(this, AgentIdentificationService.class, null)).getName();

    Classification classification = 
      imessage.createClassification("LOGINFAILURE", null);
    MRAgentLookUp lookup = new MRAgentLookUp( null, null, null, null, 
                                              classification, null, null, true );
    ClusterIdentifier destination = 
      new ClusterIdentifier(_societySecurityManager);
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
      processLoginFailure();
    }
    if (_sensors.hasChanged()) {
      updateSensors();
    }
  }

  /**
   * Copy the login failure to the blackboard
   */
  protected void processLoginFailure() {
    Enumeration queryResults = _loginFailureQuery.getChangedList();
    while (queryResults.hasMoreElements()) {
      QueryResultAdapter queryResult = 
        (QueryResultAdapter) queryResults.nextElement();
    AggregationResultSet results = queryResult.getResultSet();
    if (results.exceptionThrown()) {
      _log.error("Exception when executing query: " + results.getExceptionSummary());
      _log.debug("XML: " + results.toXml());
    } else {
      Iterator atoms = results.getAllAtoms();
      BlackboardService bbs = getBlackboardService();
      DocumentBuilder parser;
      try {
        parser = _parserFactory.newDocumentBuilder();
      } catch (ParserConfigurationException e) {
        _log.error("Can't parse any events. The parser factory isn't configured properly.");
        _log.debug("Configuration error.", e);
        return;
      }
      while (atoms.hasNext()) {
        ResultSetDataAtom d = (ResultSetDataAtom) atoms.next();
        String owner = d.getIdentifier("owner").toString();
        String id = d.getIdentifier("id").toString();
        String source = d.getValue("source").toString();
        String xml = d.getValue("event").toString();

        Event event = new EventImpl(new UID(owner,Long.parseLong(id)),
                                    new ClusterIdentifier(source),
                                    IDMEF_Message.createMessage(xml));
          
        bbs.publishAdd(event);
      }
    }
    }
  }

  /**
   * Updates the Aggregation Query to use the changed sensor capabilities list
   */
  private synchronized void updateSensors() {
    Enumeration e = _sensors.getChangedList();

    QueryResultAdapter qra = createQuery();
    AggregationQuery query = qra.getQuery();

    while (e.hasMoreElements()) {
      CmrRelay relay = (CmrRelay) e.nextElement();
      MRAgentLookUpReply reply = (MRAgentLookUpReply) relay.getResponse();
      List agents = reply.getAgentList();
      Iterator iter = agents.iterator();
      while (iter.hasNext()) {
        String agent = iter.next().toString();
        if (!_agents.contains(agent)) {
          query.addSourceCluster(agent);
          _agents.add(agent);
        }
      }
    }

    if (!query.getSourceClusters().hasMoreElements()) {
      // nothing new
      return;
    }

    synchronized (_queryAdapters) {
      _queryAdapters.add(qra);
    }

    getBlackboardService().publishAdd(qra);
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
      return (obj instanceof Event);
    }
  }

  public static class FormatLoginFailure implements IncrementFormat {
    // IncrementFormat API
    public void encode(UpdateDelta out, SubscriptionAccess sacc) {
      Collection addTo = out.getAddedList();
      Collection added = sacc.getAddedCollection();
      out.setReplacement(true);

      if (added == null) {
        return;
      }

      Iterator iter = added.iterator();
      ConfigFinder cf = new ConfigFinder();
      IDMEF_Message.setDtdFileLocation(cf.locateFile("idmef-message.dtd").toString());
      while (iter.hasNext()) {
        Event event = (Event) iter.next();
        ResultSetDataAtom da = new ResultSetDataAtom();
        UID uid = event.getUID();
        da.addIdentifier("owner", uid.getOwner());
        da.addIdentifier("id", String.valueOf(uid.getId()));
        da.addValue("source", event.getSource().toAddress());
        da.addValue("event", event.getEvent().toString());
        addTo.add(da);
      }
    }
  }

}
