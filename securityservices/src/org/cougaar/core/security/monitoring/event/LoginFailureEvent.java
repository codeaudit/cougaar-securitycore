/*
 * <copyright>
 *  Copyright 1997-2002 Network Associates
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

package org.cougaar.core.security.monitoring.event;

import edu.jhuapl.idmef.Classification;
import org.cougaar.core.security.constants.IdmefClassifications;

public class LoginFailureEvent extends FailureEvent {
  public static final String FAILURE_REASON = "LOGIN_FAILURE_REASON";
  public static final Classification LOGINFAILURE =
    new Classification(IdmefClassifications.LOGIN_FAILURE, "", Classification.VENDOR_SPECIFIC);

  public static final String FAILURE_REASONS[] = {
    "USER_DOES_NOT_EXIST",
    "DATABASE_ERROR",
    "INVALID_USER_CERTIFICATE",
    "INVALID_SUBJECT",
    "DISABLED_ACCOUNT",
    "NULL_DB_PASSWORD",
    "WRONG_PASSWORD",
    "CERTIFICATE_REQUIRED",
    "INSUFFICIENT_PRIVILEGES"};

  private String [] m_source;
  private String [] m_target;

  public final static String REASON_ID = "LOGIN_FAILURE_REASON";
  public final static String DATA_ID = "LOGIN_FAILURE_DATA";
  public LoginFailureEvent(String [] source, String [] target, String reason, String data){
    super(IdmefClassifications.LOGIN_FAILURE, null,
      null, reason, REASON_ID, data, DATA_ID);

    m_source = source;
    m_target = target;
  }

  public String [] getEventSource() {
    return m_source;
  }

  public String [] getEventTarget() {
    return m_target;
  }

}
