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
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.idmef.Agent;

// Cougaar overlay
import org.cougaar.core.security.constants.IdmefClassifications;
import org.cougaar.core.security.constants.AdaptiveMnROperatingModes;

import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.XMLSerializable;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.NoSuchElementException;
import java.util.TimerTask;
import java.util.Enumeration;
//import javax.naming.NamingException;

/**
 * This class queries message failures and will revoke an agent
 * certificate if the number of maximum message failures are exceeded. 
 * The value for maximum number of message failures is obtained through
 * the MAX_MESSAGE_FAILURE Operating Modes driven by the adaptivity engine.
 * Add these lines to your agent:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.CertificateRevokerPlugin(600,86400)
 * plugin = org.cougaar.core.security.monitoring.plugin.EventQueryPlugin(SocietySecurityManager,org.cougaar.core.security.monitoring.plugin.AllMessageFailures)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 * Here, the number 600 is the duration to wait (in seconds) between checking
 * the message failures for deletion. 86400 represents the amount of time to
 * keep the message failures before deleting it. SocietySecurityManager is
 * the agent name of the society security manager.
 */
public class CertificateRevokerPlugin extends ComponentPlugin {
  private int  m_maxFailures   = 3;
  private long m_cleanInterval = 1000 * 60 * 10;      // 10 minutes
  private long m_rememberTime  = 1000 * 60 * 60;      // 1 hour

  FailureCache m_failures       = new FailureCache();
  private LoggingService  m_log;
  private IncrementalSubscription m_maxMessageFailureSubscription;

  private OperatingMode m_maxMessageFailureOM = null;

  /**
   * Subscription to the message failures on the local blackboard
   */
  protected IncrementalSubscription m_messageFailureQuery;

  /**
   * The predicate indicating that we should retrieve all new
   * message failures
   */
  private static final UnaryPredicate MESSAGE_FAILURES_PREDICATE = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof Event) {
          IDMEF_Message msg = ((Event) o).getEvent();
          if (msg instanceof Alert) {
            Alert alert = (Alert) msg;
            Classification cs[] = alert.getClassifications();
            if (cs != null) {
              for (int i = 0; i < cs.length; i++) {
                if (IdmefClassifications.MESSAGE_FAILURE.equals(cs[i].getName())) {
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
   * Max message failure operating mode range
   */
  private static final OMCRangeList MAX_MESSAGE_FAILURE_RANGE =
      new OMCRangeList(new OMCThruRange(1.0, Double.MAX_VALUE ));

  private static final String MAX_MESSAGE_FAILURES = AdaptiveMnROperatingModes.MAX_MESSAGE_FAILURES;

  /**
   * For the max message failure OperatingMode
   */
  private static final UnaryPredicate MAX_MESSAGE_FAILURE_PREDICATE =
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof OperatingMode) {
          OperatingMode om = (OperatingMode) o;
          String omName = om.getName();
          if (MAX_MESSAGE_FAILURES.equals(omName)) {
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
      m_cleanInterval = Long.parseLong(param) * 1000;

      paramName = "failure memory";
      param = iter.next().toString();
      m_rememberTime = Long.parseLong(param) * 1000;
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
    if (m_cleanInterval <= 0 || m_rememberTime <= 0) {
      throw new IllegalArgumentException("You must provide positive " +
                                         "clean interval and failure memory " +
                                         "arguments");
    }
  }

  /**
   * revoke an agent's certificate
   */
  private void revokeCertificate(String agent) {
    // throws Exception {
    m_log.debug("revoking certificate of agent(" + agent + ")");
    // get a handle to the ca and revoke the agent's certificate
  }

  protected void setupSubscriptions() {
    m_log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);
    
    //m_userService = (LdapUserService)
	//getServiceBroker().getService(this, LdapUserService.class, null);
    BlackboardService blackboard = getBlackboardService();

    m_messageFailureQuery = (IncrementalSubscription)
      blackboard.subscribe(MESSAGE_FAILURES_PREDICATE);
    m_maxMessageFailureSubscription = (IncrementalSubscription)
      blackboard.subscribe(MAX_MESSAGE_FAILURE_PREDICATE);
    
    // read init values from config file and set operating modes accordingly
    m_maxMessageFailureOM = new OperatingModeImpl(MAX_MESSAGE_FAILURES, 
                                               MAX_MESSAGE_FAILURE_RANGE, 
                                               new Double(m_maxFailures));
    
    blackboard.publishAdd(m_maxMessageFailureOM);

    ThreadService ts = (ThreadService) getServiceBroker().
      getService(this, ThreadService.class, null);
    ts.schedule(m_failures,
                0, ((long)m_cleanInterval) * 1000);
  }

  public void execute() {
    if (m_maxMessageFailureSubscription.hasChanged()) {
      updateMaxMessageFailures();
    }
    if (m_messageFailureQuery.hasChanged()) {
      processMessageFailure();
    }
  }

  private void updateMaxMessageFailures() {
    Collection oms = m_maxMessageFailureSubscription.getChangedCollection();
    Iterator i = oms.iterator();
    OperatingMode om = null;
    if (oms.size() > 0) {
      om = (OperatingMode)i.next();
      m_log.debug("Max message failures updated to " + om.getValue() + ".");
      m_maxFailures = (int) Double.parseDouble(om.getValue().toString());
    }
  }

  /**
   * Process a new message failure IDMEF event.
   */
  private void processMessageFailure() {
    Enumeration iter = m_messageFailureQuery.getAddedList();

    while (iter.hasMoreElements()) {
      Event e = (Event) iter.nextElement();
      Alert alert = (Alert) e.getEvent();
      Source srcs[] = alert.getSources();
      AdditionalData data[] = alert.getAdditionalData();
      if (srcs != null) {
	for (int i = 0; i < srcs.length; i++) {
	  Agent agent = findAgent(srcs[i].getIdent(), data); 
	  if (agent != null) {
	    Address addr = agent.getAddress();
	    if (addr != null) {
	      m_failures.add(addr.getAddress());
	    }
	  }
	}
      }
    }
  }

  // find the agent information in the additional data that references ident
  private Agent findAgent(String ident, AdditionalData []data) {
    for(int i = 0; i < data.length; i++) {
      AdditionalData d = data[i];
      if(d.getMeaning().equals(Agent.SOURCE_MEANING) && 
         d.getType().equals(AdditionalData.XML)) {
        XMLSerializable xmlData = d.getXMLData();
        if(xmlData != null &&
           (xmlData instanceof Agent)) {
          Agent agent = (Agent)xmlData;
          String []refIdents = agent.getRefIdents();
          for(int j = 0; j < refIdents.length; j++) {
            if(ident.equals(refIdents[j])) {
              return agent;
            }
          }
        }
      }
    }
    return null;  
  }

  private class FailureCache extends TimerTask {
    HashMap m_failures = new HashMap();
    
    public FailureCache() {
    }

    public void add(String agent) {
      boolean revokeCert = false;
      CacheNode failure = null;
      synchronized (m_failures) {
        failure = (CacheNode) m_failures.get(agent);
        if (failure == null) {
          failure = new CacheNode();
          m_failures.put(agent, failure);
        }
        failure.failureCount++;
        if (failure.failureCount >= m_maxFailures) {
          m_failures.remove(agent);
          revokeCert = true;
        }
        failure.lastFailure = System.currentTimeMillis();
      }
      if (revokeCert) {
        try {
          revokeCertificate(agent);
        } catch (Exception e) {
          m_log.error("Could not revoke certificate for agent " + agent + ": " + e.getMessage());
          synchronized (m_failures) {
            m_failures.put(agent, failure); // put it back in...
          }
        }
      }
    }

    public void run() {
      long deleteTime = System.currentTimeMillis() - m_rememberTime;
      synchronized (m_failures) {
        Iterator iter = m_failures.entrySet().iterator();
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
