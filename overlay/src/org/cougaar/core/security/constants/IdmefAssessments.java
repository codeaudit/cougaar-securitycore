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
 * This class defines all of the Idmef Assessment constants.
 *
 * Place all Idmef Assessment constants here.
 */
public class IdmefAssessments {
  /**
   * cougaar assessment name prefix
   */
  public final static String COUGAAR_PREFIX = "org.cougaar.core.security.monitoring.";
  // assessment action description strings.  the category of the action should be 'Action.OTHER'.
  /**
   * certificate revocation
   */
  public final static String CERTIFICATE_REVOKED = 
    COUGAAR_PREFIX + "CERTIFICATE_REVOKED";
  /**
   * user lockout
   */
  public final static String USER_LOCKOUT = 
    COUGAAR_PREFIX + "USER_LOCKOUT";
}
