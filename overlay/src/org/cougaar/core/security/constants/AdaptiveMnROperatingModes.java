/*
 * <copyright>
 *  Copyright 1997-2002 Networks Associates Technology, Inc.
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
 
package org.cougaar.core.security.constants;

/**
 * This class specifies the operating modes subscribed by various sensors
 * and analyzers developed by the Ultra*Log project teams.  These operating
 * modes are also used to define plays in an adaptivity playbook.
 *
 * Place all operating mode name constants in this class.
 */
public class AdaptiveMnROperatingModes {
  /**
   * number of login failures before locking out a user
   * possible value: { N, where N is a number }
   */
  public final static String MAX_LOGIN_FAILURES = 
    "org.cougaar.core.security.monitoring.MAX_LOGIN_FAILURES";
  /**
   * the lockout duration
   * possible value: { N, where N is a number in minutes }
   */
  public final static String LOCKOUT_DURATION = 
    "org.cougaar.core.security.monitoring.LOCKOUT_DURATION";
  /**
   * threat con level 
   * possible values: { LOW | HIGH }
   */
  public final static String THREATCON_LEVEL = 
    "org.cougaar.core.security.monitoring.THREATCON_LEVEL";
  /**
   * policy preventive measure
   * possible values: { LOW | HIGH }
   */
  public final static String PREVENTIVE_MEASURE_POLICY = 
    "org.cougaar.core.security.policy.PREVENTIVE_MEASURE_POLICY";
  /**
   * number of message failure before revoking an agent's certificate
   * possible values: { N, where N is a number }
   */
  public final static String MAX_MESSAGE_FAILURES = 
    "org.cougaar.core.security.crypto.MAX_MESSAGE_FAILURES";
  /**
   * telcordia's adaptive filter scope
   * possible values: 
   * { LOGIN_FAILURES | LOGIN_JAR_SECURITYMGR_FAILURES | 
   *   LOGIN_JAR_SECURITYMGR_CRYPTO_FAILURES }
   */
  public final static String ADAPTIVE_FILTER_SCOPE = 
    "com.telcordia.mode.AdaptiveFilterOperatingModeScope";
  /**
   *  telcordia's adaptive filter reporting rate
   *  possible values: { MODERATE | RAPID }
   */
  public final static String ADAPTIVE_FILTER_REPORTING_RATE = 
    "com.telcordia.mode.AdaptiveFilterOperatingModeReportingRate";
}
