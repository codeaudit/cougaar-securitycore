/*
 * <copyright>
 *  Copyright 1997-2002 Networks Associates Inc
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
package org.cougaar.core.security.test.adaptivity;

import org.cougaar.core.adaptivity.OMCRange;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.OMCThruRange;
import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.adaptivity.OperatingModeCondition;
import org.cougaar.core.adaptivity.OperatingModeImpl;
import org.cougaar.core.adaptivity.SensorCondition;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.persist.PersistenceState;
import org.cougaar.core.plugin.ServiceUserPlugin;
import org.cougaar.core.service.ConditionService;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Iterator;

/**
 * Plugin to arbitrarily publish a LOGIN_FAILURE_RATE and LOGIN_LOCKOUTS condition,
 * and subscribe to the MAX_LOGIN_FAILURES and LOCKOUT_DURATION operating modes.
 */
public class LoginFailureAnalyzerPlugin extends ServiceUserPlugin {
  // conditions
  private static final String FAILURE_RATE = "org.cougaar.core.security.monitoring.LOGIN_FAILURE_RATE";
  private static final String LOCKOUT_RATE = "org.cougaar.core.security.monitoring.LOGIN_LOCKOUTS";
  private static final String PRECEIVED_THREAT_LEVEL = "org.cougaar.core.security.monitoring.PERCEIVED_THREAT_LEVEL";
  // operating modes
  private static final String MAX_LOGIN_FAILURES = "org.cougaar.core.security.monitoring.MAX_LOGIN_FAILURES";
  private static final String LOCKOUT_DURATION = "org.cougaar.core.security.monitoring.LOCKOUT_DURATION";
    
  private ConditionService conditionService;
  private IncrementalSubscription maxLoginFailureSubscription;
  private IncrementalSubscription lockoutDurationSubscription;
  
  private long then = System.currentTimeMillis();
  private static final long TIME_CONSTANT = 10000L; // Five second time constant
  private static final int FAILURE_RATE_MAX = 25;
  
  // failure rate 
  private static final OMCRangeList failureRateRange = 
      new OMCRangeList(new OMCThruRange(0.0, Double.MAX_VALUE));
  
  // login lockout rate
  private static final OMCRangeList lockoutRateRange = 
      new OMCRangeList(new OMCThruRange(0.0, Double.MAX_VALUE));
  
  // preceived threat level
  private static Double []ptlValues = { new Double(1), 
                                        new Double(2), 
                                        new Double(3) };
  private static final OMCRangeList preceivedThreatLevelRange = 
      new OMCRangeList(ptlValues);
  
  // operating modes
  private static OperatingMode maxLoginFailureOM = null;
  private static OperatingMode lockoutDurationOM = null;
  
  // 
  private static OMCRange []ldValues = { new OMCThruRange(-1.0, Double.MAX_VALUE) };
  private static final OMCRangeList maxLoginFailureRange = 
      new OMCRangeList(new OMCThruRange(1.0, Double.MAX_VALUE ));
  private static final OMCRangeList lockoutDurationRange = 
      new OMCRangeList(ldValues);
  
  private static int iteration = 1;
  
  /**
   * Private inner class precludes use by others to set our
   * measurement. Others can only reference the base Condition
   * class which has no setter method.
   **/
  private static class LoginFailureRateCondition extends SensorCondition implements PersistenceState {
    public LoginFailureRateCondition(String name, OMCRangeList allowedValues, Comparable value) {
      super(name, allowedValues, value);
    }

    public void setValue(Comparable newValue) {
      super.setValue(newValue);
    }
  }
  
  private static class LockoutRateCondition extends SensorCondition implements PersistenceState {
    public LockoutRateCondition(String name, OMCRangeList allowedValues, Comparable value) {
      super(name, allowedValues, value);
    }

    public void setValue(Comparable newValue) {
      super.setValue(newValue);
    }
  } 
  
  private static class PreceivedThreatLevelMC extends OperatingModeCondition implements PersistenceState {
    public PreceivedThreatLevelMC(String name, OMCRangeList allowedValues, Comparable value) {
      super(name, allowedValues, value);
    }

    public void setValue(Comparable newValue) {
      super.setValue(newValue);
    }
  } 

  private UnaryPredicate maxLoginFailurePredicate = new UnaryPredicate() {
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
  
  private UnaryPredicate lockoutDurationPredicate = new UnaryPredicate() {
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
  private static final Class[] requiredServices = {
    ConditionService.class
  };

  public LoginFailureAnalyzerPlugin() {
    super(requiredServices);
  }

  protected void setupSubscriptions() {
    String poll = getParameters().iterator().next().toString();
    LoginFailureRateCondition failureRate =
      new LoginFailureRateCondition(FAILURE_RATE, failureRateRange, new Double(0));
    
    LockoutRateCondition loginLockouts =
      new LockoutRateCondition(LOCKOUT_RATE, lockoutRateRange, new Double(0));
    
    PreceivedThreatLevelMC preceivedThreatLevel =
      new PreceivedThreatLevelMC(PRECEIVED_THREAT_LEVEL, preceivedThreatLevelRange, new Double(1));
    
    // read init values from config file and set operating modes accordingly
    maxLoginFailureOM = new OperatingModeImpl(MAX_LOGIN_FAILURES, maxLoginFailureRange, new Double(10));
    lockoutDurationOM = new OperatingModeImpl(LOCKOUT_DURATION, lockoutDurationRange, new Double(300));
    
    blackboard.publishAdd(failureRate);
    blackboard.publishAdd(loginLockouts);
    // blackboard.publishAdd(preceivedThreatLevel);
    maxLoginFailureSubscription = (IncrementalSubscription)blackboard.subscribe(maxLoginFailurePredicate);
    lockoutDurationSubscription = (IncrementalSubscription)blackboard.subscribe(lockoutDurationPredicate);
    blackboard.publishAdd(maxLoginFailureOM);
    blackboard.publishAdd(lockoutDurationOM);
    if (haveServices()) resetTimer(TIME_CONSTANT);
  }

  /**
   * Test if all needed services have been acquired. Test the
   * conditionService variable for null. If still null ask
   * acquireServices to continue trying to acquire services. If true
   * is returned, fill in the service variables and return true.
   * Subsequent calls will return true immediately.
   **/
  private boolean haveServices() {
    if (conditionService != null) return true;
    if (acquireServices()) {
      ServiceBroker sb = getServiceBroker();
      conditionService = (ConditionService)
        sb.getService(this, ConditionService.class, null);
      return true;
    }
    return false;
  }

  protected void execute() {
    if (haveServices()) {
      if (timerExpired()) {
        // the timer went off, update the login failure rate and lockout rate
        cancelTimer();
        updateLoginFailureRate();
        updatelockoutRate();
        resetTimer(TIME_CONSTANT);
      }
      else {
        // one of our subscriptions caused execute() to be invoked
        if (maxLoginFailureSubscription.hasChanged()) {
          updateMaxLoginFailures();
        }
        if (lockoutDurationSubscription.hasChanged()) {
          updateLockoutDuration();
        }
      }
    }
  }

  private void updateLoginFailureRate() {
    logger.debug("Getting " + FAILURE_RATE + " from conditionService");
    LoginFailureRateCondition loginFailureRate =
      (LoginFailureRateCondition)conditionService.getConditionByName(FAILURE_RATE);
    
    if (loginFailureRate != null) {
      Double i = (Double)loginFailureRate.getValue();
      int rate = i.intValue();
      rate += 1;
      if((rate % 25) == 0) {
        rate = 0;
      }
      logger.debug("Setting " + FAILURE_RATE + " = " + rate);
      loginFailureRate.setValue(new Double(rate));
      blackboard.publishChange(loginFailureRate);
    }
  }
  
   private void updatelockoutRate() {
    logger.debug("Getting " + LOCKOUT_RATE + " from conditionService");
    LockoutRateCondition loginLockouts =
      (LockoutRateCondition)conditionService.getConditionByName(LOCKOUT_RATE);
    
    if (loginLockouts != null) {
      Double i = (Double)loginLockouts.getValue();
      int rate = i.intValue();
      
      if ((iteration++ % 5) == 0) {
        rate++;
        iteration = 1;
      }
      
      logger.debug("Setting " + LOCKOUT_RATE + " = " + rate);
      loginLockouts.setValue(new Double(rate));
      blackboard.publishChange(loginLockouts);
    }
  }
  
  private void updateMaxLoginFailures() {
    Collection oms = maxLoginFailureSubscription.getChangedCollection();
    Iterator i = oms.iterator();
    OperatingMode om = null;
    if(oms.size() > 0) {
      om = (OperatingMode)i.next();
      logger.debug("Max Login Failures updated to " + om.getValue() + ".");
    }
    else {
      logger.error("maxLoginFailureSubscription.getChangedCollection() returned collection of size 0!");
    }    
  }
  
  private void updateLockoutDuration() {
    Collection oms = lockoutDurationSubscription.getChangedCollection();
    Iterator i = oms.iterator();
    OperatingMode om = null;
    if(oms.size() > 0) {
      om = (OperatingMode)i.next();
      logger.debug("Lockout Duration updated to " + om.getValue() + " seconds.");
    }
    else {
      logger.error("lockoutDurationSubscription.getChangedCollection() returned collection of size 0!");
    }
  }
}
