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
import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.core.agent.ClusterIdentifier;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.AgentIdentificationService;
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
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.services.crypto.LdapUserService;
import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUpReply;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;

// Cougaar overlay
import org.cougaar.core.security.constants.IdmefClassifications;
import org.cougaar.core.security.constants.AdaptiveMnROperatingModes;
import org.cougaar.core.security.constants.IdmefAssessments;

import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.IDMEF_Process;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.User;
import edu.jhuapl.idmef.UserId;
import edu.jhuapl.idmef.DetectTime;
import edu.jhuapl.idmef.Assessment;
import edu.jhuapl.idmef.Impact;
import edu.jhuapl.idmef.Confidence;
import edu.jhuapl.idmef.Action;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.NoSuchElementException;
import java.util.TimerTask;
import java.util.Enumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

/**
 * This class queries login failures and will lockout users who
 * have failed to login too many times. The values for maximum
 * login failures and lockout duration are retrieved from
 * Operating Modes driven by the adaptivity engine.
 * Add these lines to your agent:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.UserLockoutPlugin(600,86400)
 * plugin = org.cougaar.core.security.monitoring.plugin.EventQueryPlugin(SocietySecurityManager,org.cougaar.core.security.monitoring.plugin.AllLoginFailures)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 * Here, the number 600 is the duration to wait (in seconds) between checking
 * the login failures for deletion. 86400 represents the amount of time to
 * keep the login failures before deleting it. SocietySecurityManager is
 * the agent name of the society security manager.
 */
public class UserLockoutPlugin extends ComponentPlugin {
  int  _maxFailures   = 3;
  long _cleanInterval = 1000 * 60 * 10;      // 10 minutes
  long _rememberTime  = 1000 * 60 * 60;      // 1 hour
  long _lockoutTime   = 1000 * 60 * 60 * 24; // 1 day

  FailureCache _failures       = new FailureCache();
  private LoggingService  _log;
  private DomainService  _domainService;
  private LdapUserService _userService;
  private IncrementalSubscription _maxLoginFailureSubscription;
  private IncrementalSubscription _lockoutDurationSubscription;

  private OperatingMode _maxLoginFailureOM = null;
  private OperatingMode _lockoutDurationOM = null;
  private static final SensorInfo _sensor = new ULSensor();
  private IdmefMessageFactory  _idmefFactory;
  private CmrFactory _cmrFactory;
  private String         _managerRole   = "SecurityMnRManager-Enclave";

  private final static Action[] USER_LOCKOUT_ACTION = new Action[] {
    new Action(Action.OTHER, IdmefAssessments.USER_LOCKOUT)
  };
  private final static Confidence USER_LOCKOUT_CONFIDENCE = 
    new Confidence(Confidence.MEDIUM, null);
  public static final Classification LOGIN_FAILURE = 
    new Classification(IdmefClassifications.LOGIN_FAILURE, "", 
                       Classification.VENDOR_SPECIFIC);
  private final static Assessment USER_LOCKOUT_ASSESSMENT = 
    new Assessment(new Impact(Impact.MEDIUM, Impact.SUCCEEDED,
                              Impact.USER, IdmefAssessments.USER_LOCKOUT),
                   USER_LOCKOUT_ACTION,
                   USER_LOCKOUT_CONFIDENCE);

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
                  AdditionalData ad[] = alert.getAdditionalData();
                  if (ad != null) {
                    for (int j = 0; j < ad.length; j++) {
                      if (KeyRingJNDIRealm.FAILURE_REASON.equals(ad[j].getMeaning())) {
                        return (KeyRingJNDIRealm.FAILURE_REASONS[KeyRingJNDIRealm.LF_PASSWORD_MISMATCH].equals(ad[j].getAdditionalData()));
                      }
                    }
                  }
                  return false;
                }
              }
            }
          }
        }
        return false;
      }
    };
    
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

  private static final String MAX_LOGIN_FAILURES = AdaptiveMnROperatingModes.MAX_LOGIN_FAILURES;
  private static final String LOCKOUT_DURATION = AdaptiveMnROperatingModes.LOCKOUT_DURATION;

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
   * Produce the Assessment alert
   */
  private void alertAssessment(String user) {
    ArrayList cfs = new ArrayList();
    cfs.add(LOGIN_FAILURE);
    Alert alert = _idmefFactory.createAlert(_sensor, new DetectTime(),
                                            null, null, cfs, null);
    
    // set the target
    UserId uid = new UserId( user, null, null, UserId.TARGET_USER );
    UserId uids[] = new UserId[] { uid };
    User u = new User( uids, null, User.UNKNOWN );
    Target t = new Target(null, u, null, null, null, null,
                          Target.UNKNOWN, null);
    alert.setTargets( new Target[] {t} );
    alert.setAssessment(USER_LOCKOUT_ASSESSMENT);
    NewEvent event = _cmrFactory.newEvent(alert);

    getBlackboardService().publishAdd(event);
  }

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
    if (iter.hasNext()) {
      _managerRole = (String) iter.next();
    } // end of if (iter.hasNext())
    
  }

  /**
   * Lockout a given user for the lockout duration
   */
  public void lock(String user) throws NamingException {
    if (_log.isDebugEnabled()) {
      _log.debug("locking out user (" + user + ")");
    } // end of if (_log.isDebugEnabled())

    // send an IDMEF alert
    alertAssessment(user);
    
    if (_lockoutTime < 0) {
      _userService.disableUser(user);
    } else {
      _userService.disableUser(user, _lockoutTime);
    }
  }

  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);
    
    _userService = (LdapUserService)
	getServiceBroker().getService(this, LdapUserService.class, null);
    BlackboardService blackboard = getBlackboardService();

    _loginFailureQuery = (IncrementalSubscription)
      blackboard.subscribe(LOGIN_FAILURES_PREDICATE);
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
    ts.schedule(_failures,
                0, ((long)_cleanInterval) * 1000);

    setupFailureSensor();
  }

  private void setupFailureSensor() {
    BlackboardService    bbs          = getBlackboardService();
    DomainService        ds           = getDomainService(); 
    _cmrFactory                       = (CmrFactory) ds.getFactory("cmr");
    _idmefFactory                     = _cmrFactory.getIdmefMessageFactory();
    ServiceBroker        sb           = getBindingSite().getServiceBroker();
    AgentIdentificationService ais    = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null);
    String               agentName    = ais.getName();
    MessageAddress       myAddress    = ais.getMessageAddress();
    CommunityService     cs           = (CommunityService)
      sb.getService(this, CommunityService.class,null);

    if (cs == null) {
      _log.error("You must have CommunityPlugin in this agent for the UserLockoutPlugin to work");
    } // end of if (cs == null)
    
    List capabilities = new ArrayList();
    capabilities.add(KeyRingJNDIRealm.LOGINFAILURE);
      
    RegistrationAlert reg = 
      _idmefFactory.createRegistrationAlert( _sensor, capabilities,
                                             _idmefFactory.newregistration ,
                                             _idmefFactory.SensorType );
    
    IDMEF_Node node = _idmefFactory.getNodeInfo();
    IDMEF_Process process = _idmefFactory.getProcessInfo();
    Source source = new Source(node, null, process, null, null, null, null);
    reg.setSources(new Source[] { source });
    
    NewEvent regEvent = _cmrFactory.newEvent(reg);
    Collection communities = cs.listParentCommunities(agentName);
    Iterator iter = communities.iterator();
    boolean addedOne = false;
    while (iter.hasNext()) {
      String community = iter.next().toString();
      Attributes attrs = cs.getCommunityAttributes(community);
      boolean isSecurityCommunity = false;
      if (attrs != null) {
        Attribute  attr  = attrs.get("CommunityType");
        if (attr != null) {
          try {
            for (int i = 0; !isSecurityCommunity && i < attr.size(); i++) {
              if ("Security".equals(attr.get(i).toString())) {
                isSecurityCommunity = true;
              }
            }
          } catch (NamingException e) {
            // error reading value, so it can't be a Security community
          }
        }
      }
      if (isSecurityCommunity) {
        AttributeBasedAddress messageAddress = 
          new AttributeBasedAddress(community, "Role", _managerRole);
        CmrRelay relay = _cmrFactory.newCmrRelay(regEvent, messageAddress);
        if (_log.isInfoEnabled()) {
          _log.info("Sending sensor capabilities to community '" + 
                    community + "'");
        }
        bbs.publishAdd(relay);
        addedOne = true;
      }
    }
    if (!addedOne) {
      _log.warn("This agent does not belong to any community. Login failures won't be reported.");
    }
  }

  public void execute() {
    if (_maxLoginFailureSubscription.hasChanged()) {
      updateMaxLoginFailures();
    }
    if (_lockoutDurationSubscription.hasChanged()) {
      updateLockoutDuration();
    }
    if (_loginFailureQuery.hasChanged()) {
      processLoginFailure();
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
    }
  }

  /**
   * Process a new login failure IDMEF event.
   */
  private void processLoginFailure() {
    Enumeration iter = _loginFailureQuery.getAddedList();

    while (iter.hasMoreElements()) {
      Event e = (Event) iter.nextElement();
      Alert alert = (Alert) e.getEvent();
      Target ts[] = alert.getTargets();
      for (int i = 0; i < ts.length; i++) {
        User user = ts[i].getUser();
        if (user != null) {
          UserId uids[] = user.getUserIds();
          if (uids != null) {
            for (int j = 0 ; j < uids.length; j++) {
              _failures.add(uids[j].getName());
            }
          }
        }
      }
    }
  }

  private class FailureCache extends TimerTask {
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

  private static class ULSensor implements SensorInfo {

    public String getName() {
      return "User Lockout Analyzer";
    }

    public String getManufacturer() {
      return "NAI Labs";
    }

    public String getModel() {
      return "Servlet Login Failure";
    }
    
    public String getVersion() {
      return "1.0";
    }

    public String getAnalyzerClass() {
      return "org.cougaar.core.security.monitoring.plugin.UserLockoutPlugin";
    }
  }
}
