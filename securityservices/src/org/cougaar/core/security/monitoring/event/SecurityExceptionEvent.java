/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.monitoring.event;

import org.cougaar.core.security.constants.IdmefClassifications;

import java.security.Principal;
import java.util.Date;

import edu.jhuapl.idmef.Classification;

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
