/*
 * <copyright>
 *  Copyright 1997-2002 Cougaar Software, Inc.
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
import edu.jhuapl.idmef.DetectTime;
import org.cougaar.core.security.constants.IdmefClassifications;

import java.security.Principal;
import java.util.Date;

/**
 * Event used for Security Manager Exceptions and Jar Verification Exceptions
 */
public class SecurityExceptionEvent extends FailureEvent {
  
  public static final Classification SECURITY_MGR_EXCEPTION =
    new Classification(IdmefClassifications.SECURITY_MANAGER_EXCEPTION, "", Classification.VENDOR_SPECIFIC);
  public static final Classification JAR_VERIFY_FAILURE =
    new Classification(IdmefClassifications.JAR_VERIFICATION_FAILURE, "", Classification.VENDOR_SPECIFIC);
    
  public final static String REASON_ID = "SECURITY_EXCEPTION_REASON";
  public final static String DATA_ID = "SECURITY_EXCEPTION_DATA";
  
  public final static String PRINCIPAL_ID = "PRINCIPAL_INFO";
  public final static String STACKTRACE_ID = "STACK_TRACE";
  
  private Principal [] _principals;
  private String _stackTrace;
  
  public SecurityExceptionEvent(String source, String target, String reason, String data,
                                String classification, Principal [] principals, String stackTrace,
                                Date detectTime){
    super(classification, source, target, reason, REASON_ID, data, DATA_ID, detectTime);
    _principals = principals;
    _stackTrace = stackTrace;
  }
  
  public Principal [] getPrincipals() {
    return _principals; 
  }
  public String getStackTrace() {
    return _stackTrace; 
  }
}