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
import java.util.LinkedList;
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

// Cougaar overlay
import org.cougaar.core.security.constants.IdmefClassifications;

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
 * This class queries for IDMEF messages and keeps
 * an updated list of Sensors with the capability. All events
 * are copied the blackboard. You must provide the name of the
 * Society Security Manager, a UnaryPredicate class that
 * selects the IDMEF messages and a class name that supports the
 * QueryClassificationProvicer interface. A single class may support
 * both.<p>
 * For example, if you want to suppor login
 * failure rate calculation and user lockout, you would have the
 * following in your configuration:
 * <pre>
 * plugin = org.cougaar.core.security.monitorin.plugin.RateCalculatorPlugin(20,60,org.cougaar.core.security.monitoring.LOGIN_FAILURE,org.cougaar.core.security.monitoring.LOGIN_FAILURE_RATE)
 * plugin = org.cougaar.core.security.monitoring.plugin.UserLockoutPlugin(600,86400)
 * plugin = org.cougaar.core.security.monitoring.plugin.EventQueryPlugin(SocietySecurityManager,org.cougaar.core.security.monitoring.plugin.AllLoginFailures)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 */
public class EventQueryPlugin extends ComponentPlugin {

  private LoggingService  _log;

  /** the current agent's name */
  private String _agentName;


  /** format script for the aggregation query */
  private static final ScriptSpec FORMAT_SPEC =
    new ScriptSpec(Language.JAVA, XmlFormat.INCREMENT, 
                   FormatEvent.class.getName());

  /** Aggregation query subscription */
  protected IncrementalSubscription _eventQuery;

  /** Sensor list update subscription */
  protected IncrementalSubscription _sensors;

  /** 
   * Results of the subscription are only going to belong to the 
   * a member of the _queryAdapters variable.
   */
  protected HashSet         _queryAdapters = new HashSet();

  /**
   * A set of agents that have the required sensor capabilities.
   */
  protected HashSet         _agents = new HashSet();

  /**
   * for set/get DomainService
   */
  protected DomainService  _domainService;

  /**
   * List of classifications to query
   */
  protected String         _classifications[];

  /**
   * The predicate script for selecting which events to copy
   */
  protected ScriptSpec     _predSpec;

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
  private UnaryPredicate _eventPredicate =
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
   * creates the AggregationQuery for use in searching for
   * IDMEF messages
   */
  protected QueryResultAdapter createQuery() {
    AggregationQuery aq = new AggregationQuery(QueryType.PERSISTENT);
    aq.setName("Event Query");
    aq.setUpdateMethod(UpdateMethod.PUSH);
    aq.setPredicateSpec(_predSpec);
    aq.setFormatSpec(FORMAT_SPEC);
    QueryResultAdapter qra = new QueryResultAdapter(aq);
    qra.setResultSet(new EQAggregationResultSet());
    return qra;
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

    if (l.size() <= 1) {
      throw new IllegalArgumentException("You must provide the Society Security Manager name, and class names for the Unary Predicate and QueryClassificationProvider");
    }

    _societySecurityManager = (String) l.remove(0);
    if (_log == null && getServiceBroker() != null) {
      _log = (LoggingService)
        getServiceBroker().getService(this, LoggingService.class, null);
    }
    if (_log != null) {
      _log.info("Setting security manager agent name to " + _societySecurityManager);
    }
    QueryClassificationProvider qcp = null;
    String up = null;
    String className = "<not found>";
    try {
      while (l.size() > 0) {
        className = (String) l.remove(0);
        Class c = Class.forName(className);
        if (QueryClassificationProvider.class.isAssignableFrom(c)) {
          if (qcp != null) {
            if (!c.isInstance(qcp)) {
              throw new IllegalArgumentException("You may have only one " +
                                                 "QueryClasssificationProvider" +
                                                 " class in the " +
                                                 "EventQueryPlugin arguments");
            } // end of if (!c.isInstance(qcp))
          } else {
            qcp = (QueryClassificationProvider) c.newInstance();
          }
        }
        if (UnaryPredicate.class.isAssignableFrom(c)) {
          if (up != null) {
            if (!className.equals(up)) {
              throw new IllegalArgumentException("You may have only one " +
                                                 "UnaryPredicate" +
                                                 " class in the " +
                                                 "EventQueryPlugin arguments");
            } // end of if (!c.isInstance(up))
          } else {
            up = className;
          } // end of else
        } // end of if (UnaryPredicate.class.isAssignableFrom(c))
      } // end of while (l.size() > 0)
    } catch (IllegalAccessException e) {
      throw new IllegalArgumentException("The class name you provided: " +
                                         className + 
                                         " could not be instantiated.");
    } catch (InstantiationException e) {
      throw new IllegalArgumentException("The class name you provided: " +
                                         className + 
                                         " could not be instantiated.");
    } catch (ClassNotFoundException e) {
      throw new IllegalArgumentException("The class name you provided: " +
                                         className + " could not be found.");
    } // end of try-catch
    
    
    if (up == null) {
      throw new IllegalArgumentException("You must provide a class name that"
                                          + " implements the UnaryPredicate " +
                                          "interface");
    } // end of if (up == null)
    if (qcp == null) {
      throw new IllegalArgumentException("You must provide a class name" +
                                         "that implements the " + 
                                         "QueryClassificationProvider " +
                                         "interface");
    } // end of if (qcp == null)
    
    _predSpec = new ScriptSpec(ScriptType.UNARY_PREDICATE, Language.JAVA, up);
    _classifications = qcp.getClassifications();
  }

  /**
   * Sets up the AggregationQuery and event subscriptions.
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);
    
    _eventQuery = (IncrementalSubscription)
      getBlackboardService().subscribe(_eventPredicate);

    ServiceBroker        sb           = getBindingSite().getServiceBroker();
    DomainService        ds           = getDomainService(); 
    CmrFactory           cmrFactory   = (CmrFactory) ds.getFactory("cmr");
    IdmefMessageFactory  imessage     = cmrFactory.getIdmefMessageFactory();
    _agentName = ((AgentIdentificationService)
                  sb.getService(this, AgentIdentificationService.class, null)).getName();

    _sensors = (IncrementalSubscription) 
      getBlackboardService().subscribe(SENSORS_PREDICATE);

    for (int i = 0 ; i < _classifications.length; i++) {
      Classification classification = 
        imessage.createClassification(_classifications[i], null);
      MRAgentLookUp lookup = new MRAgentLookUp( null, null, null, null, 
                                                classification, null, null, true );
      ClusterIdentifier destination = 
        new ClusterIdentifier(_societySecurityManager);
      CmrRelay relay = cmrFactory.newCmrRelay(lookup, destination);
      getBlackboardService().publishAdd(relay);
    } // end of for (int i = 0 ; i < classifications.length; i++)
    
  }

  /**
   * Called whenever there is an update in the AggregationQuery results
   * or there is a change to the sensors.
   * Updates the count of events for the bucket associated with
   * the current second. 
   */
  public void execute() {
    if (_eventQuery.hasChanged()) {
      processEvents();
    }
    if (_sensors.hasChanged()) {
      updateSensors();
    }
  }

  /**
   * Copy the event to the blackboard
   */
  protected void processEvents() {
    Enumeration queryResults = _eventQuery.getChangedList();
    while (queryResults.hasMoreElements()) {
      QueryResultAdapter queryResult = 
        (QueryResultAdapter) queryResults.nextElement();
    EQAggregationResultSet results = 
      (EQAggregationResultSet) queryResult.getResultSet();
    if (results.exceptionThrown()) {
      _log.error("Exception when executing query: " + results.getExceptionSummary());
      _log.debug("XML: " + results.toXml());
    } else {
      Iterator atoms = results.getAddedAtoms();
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

  public static class FormatEvent implements IncrementFormat {
    // IncrementFormat API
    public void encode(UpdateDelta out, SubscriptionAccess sacc) {
      Collection addTo = out.getAddedList();
      Collection added = sacc.getAddedCollection();
      out.setReplacement(true);

      if (added == null) {
        return;
      }

      Iterator iter = added.iterator();
      ConfigFinder cf = ConfigFinder.getInstance();
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

  /**
   * This class extends AggregationResultSet to add newgetAddedAtoms() method.
   * Many thanks to Krishna Yallapu for this code.
   */
  public static class EQAggregationResultSet extends AggregationResultSet {
    List addedAtoms = new LinkedList();

    public void incrementalUpdate (UpdateDelta delta) {
      super.incrementalUpdate(delta);
      addedAtoms.addAll(delta.getAddedList());
    }

    public Iterator getAddedAtoms () {
      List addedList = new LinkedList();
      addedList.addAll(addedAtoms);
      Iterator iter = addedList.iterator();
      addedAtoms.clear();
      return iter;
    }
  }
}
