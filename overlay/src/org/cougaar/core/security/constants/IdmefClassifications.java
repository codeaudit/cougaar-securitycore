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
 * This class defines all of the Idmef classification constants.
 *
 * Place all Idmef classification name constants here.
 */
public class IdmefClassifications {
  /**
   * cougaar classification name prefix
   */
  public final static String COUGAAR_PREFIX = "org.cougaar.core.security.monitoring.";
  /**
   * data protection failure
   * @see DataFailureEvent
   */
  public final static String DATA_FAILURE = 
    COUGAAR_PREFIX + "DATA_FAILURE";
  /**
   * message failure
   * @see MessageFailureEvent
   */
  public final static String MESSAGE_FAILURE = 
    COUGAAR_PREFIX + "MESSAGE_FAILURE";
  /**
   * login failure
   */
  public final static String LOGIN_FAILURE = 
    COUGAAR_PREFIX + "LOGIN_FAILURE";
  /**
   * security manager exception
   */
  public final static String SECURITY_MANAGER_EXCEPTION = 
    COUGAAR_PREFIX + "SECURITY_MANAGER_EXCEPTION";
  /**
   * jar verification failure
   */
  public final static String JAR_VERIFICATION_FAILURE = 
    COUGAAR_PREFIX + "JAR_VERIFICATION_FAILURE";
}
