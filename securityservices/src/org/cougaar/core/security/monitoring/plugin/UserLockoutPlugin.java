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
import org.cougaar.core.service.BlackboardService;
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
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUpReply;
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
 * plugin = org.cougaar.core.security.monitoring.plugin.UserLockoutPlugin(600,86400,org.cougaar.core.security.monitoring.MAX_LOGIN_FAILURES)
 * plugin = org.cougaar.core.security.monitoring.plugin.EventQueryPlugin(SocietySecurityManager,org.cougaar.core.security.monitoring.plugin.AllLoginFailures)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 * Here, the number 600 is the duration to wait (in seconds) between checking
 * the login failures for deletion. 86400 represents the amount of time to
 * keep the login failures before deleting it. The third argument is the name
 * of the operating mode that the plugin uses to determine when a threshold has
 * been exceed that warrants an action.
 */
public class UserLockoutPlugin extends ResponderPlugin {

  private long _lockoutTime   = 1000 * 60 * 60 * 24; // 1 day

  private LdapUserService _userService;
  private IncrementalSubscription _lockoutDurationSubscription;

  private OperatingMode _lockoutDurationOM = null;
  private static final SensorInfo _sensor = new ULSensor();

  // fixed
  private final String         _managerRole   = "SecurityMnRManager-Enclave";

  private final static Action[] USER_LOCKOUT_ACTION = new Action[] {
    new Action(Action.OTHER, IdmefAssessments.USER_LOCKOUT)
  };
  private final static Confidence USER_LOCKOUT_CONFIDENCE = 
    new Confidence(Confidence.MEDIUM, null);
    
  private final static Assessment USER_LOCKOUT_ASSESSMENT =
    new Assessment(new Impact(Impact.MEDIUM, Impact.SUCCEEDED,
                              Impact.USER, IdmefAssessments.USER_LOCKOUT),
                   USER_LOCKOUT_ACTION,
                   USER_LOCKOUT_CONFIDENCE);

  public static final Classification LOGIN_FAILURE = 
    new Classification(IdmefClassifications.LOGIN_FAILURE, "", 
                       Classification.VENDOR_SPECIFIC);
                       
  /**
   * The predicate indicating that we should retrieve all new
   * login failures
   */
  private static final UnaryPredicate LOGIN_FAILURES_PREDICATE = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof Event) {
          IDMEF_Message msg = ((Event) o).getEvent();
	  if (msg instanceof RegistrationAlert) {
	    return false;
	  }
          if (msg instanceof Alert) {
            Alert alert = (Alert) msg;
            if (alert.getAssessment() != null) {
              return false; // never look at assessment alerts
            } // end of if (alert.getAssessment() != null)
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
   * Lockout duration operating mode range
   */
  private static final OMCRangeList LOCKOUT_DURATION_RANGE =
      new OMCRangeList(LD_VALUES);

  private static final String LOCKOUT_DURATION = AdaptiveMnROperatingModes.LOCKOUT_DURATION;

  public void execute() {
    if (_lockoutDurationSubscription.hasChanged()) {
      updateLockoutDuration();
    }
    super.execute();
  }
  
  protected void setupSubscriptions() {
    super.setupSubscriptions();
   
    _userService = (LdapUserService)
	getServiceBroker().getService(this, LdapUserService.class, null);
    BlackboardService blackboard = getBlackboardService();

    _lockoutDurationSubscription = (IncrementalSubscription)
      blackboard.subscribe(LOCKOUT_DURATION_PREDICATE);
    
    _lockoutDurationOM = new OperatingModeImpl(LOCKOUT_DURATION, 
                                               LOCKOUT_DURATION_RANGE, 
                                               new Double(_lockoutTime/1000));
    
    blackboard.publishAdd(_lockoutDurationOM);
    setupFailureSensor();
  }
  
   /**
   * method that takes an action against the culprit
   */
  protected void action(String culprit) throws Exception {
    if (_log.isDebugEnabled()) {
      _log.debug("locking out user (" + culprit + ")");
    } // end of if (_log.isDebugEnabled())
    if (_lockoutTime < 0) {
      _userService.disableUser(culprit);
    } else {
      _userService.disableUser(culprit, _lockoutTime);
    } 
  }
 
  protected UnaryPredicate getFailurePredicate(){
    return LOGIN_FAILURES_PREDICATE; 
  }
  /**
   * method that creates and publishes an IDMEF message with
   * an assessment specifying the action taken in response to 
   * login failures exceeding a certain threshold.
   */ 
  protected void publishAssessment(String culprit) {
    ArrayList cfs = new ArrayList();
    cfs.add(LOGIN_FAILURE);

    UserId uid = _idmefFactory.createUserId( culprit );
    List uids = new ArrayList();
    uids.add(uid);
    User u = _idmefFactory.createUser(uids);
    Target t = _idmefFactory.createTarget(null, u, null, null, null, null);
    List targets = new ArrayList();
    targets.add(t);

    Alert alert = _idmefFactory.createAlert(_sensor, new DetectTime(),
                                            null, targets, cfs, null);
    alert.setAssessment(USER_LOCKOUT_ASSESSMENT);
    NewEvent event = _cmrFactory.newEvent(alert);

    getBlackboardService().publishAdd(event); 
  }
  
  /**
   * method to process a login failure
   */
  protected void processFailure() {
    Enumeration iter = _failureQuery.getAddedList();

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
              addCulprit(uids[j].getName());
            }
          }
        }
      }
    } 
  }
  
  private List createClassifications() {
    ArrayList cfs = new ArrayList();
    cfs.add(LOGIN_FAILURE);
    return cfs;
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
  
  private void setupFailureSensor() {
    BlackboardService    bbs          = getBlackboardService();
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
      _idmefFactory.createRegistrationAlert( _sensor, null, null,
                                             capabilities,
                                             null,
                                             _idmefFactory.newregistration ,
                                             _idmefFactory.SensorType,
                                             myAddress.toString());
    
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
