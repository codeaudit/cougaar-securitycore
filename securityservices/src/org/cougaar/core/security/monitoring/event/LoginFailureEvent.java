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

import edu.jhuapl.idmef.Classification;

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
