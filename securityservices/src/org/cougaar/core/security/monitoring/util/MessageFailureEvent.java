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

package org.cougaar.core.security.monitoring.util;

// Cougaar overlay
import org.cougaar.core.security.constants.IdmefClassifications;

/**
 * This data structure represent an Message Failure Event that could occur
 * in the AccessAgentProxy, CryptoManagerService, and MessageProtectionService
 */
public class MessageFailureEvent extends FailureEvent {
  public final static String REASON_ID = "MESSAGE_FAILURE_REASON";
  public final static String DATA_ID = "MESSAGE_FAILURE_DATA";
  // reasons
  // access agent proxy
  public final static String INCONSISTENT_IDENTIFIER = "Inconsistent Identifier";
  public final static String INCONSISTENT_MESSAGE_ACTION = "Inconsistent Message Action";
  public final static String INCONSISTENT_AGENT_ACTION = "Inconsistent Agent Action";
  public final static String INVALID_MESSAGE_CONTENTS = "Invalid Message Contents";
  // crypto manager service and message protection service
  public final static String INVALID_POLICY = "Invalid Policy";
  public final static String SIGNING_FAILURE = "Signing Failure";
  public final static String VERIFICATION_FAILURE = "Verification Failure";
  public final static String ENCRYPT_FAILURE = "Encryption Failure";
  public final static String DECRYPT_FAILURE = "Decryption Failure";
  public final static String SIGN_AND_ENCRYPT_FAILURE = "Sign and Encrypt Failure";
  public final static String DECRYPT_AND_VERIFY_FAILURE = "Decrypt and Verify Failure";
  public final static String UNKNOWN_FAILURE = "Unknown Failure";
  
  public MessageFailureEvent(String source, String target, String reason, String data){
    super(IdmefClassifications.MESSAGE_FAILURE, source, 
      target, reason, REASON_ID, data, DATA_ID);
  }
  
  public String toString(){
    StringBuffer sb = new StringBuffer(128);
    sb.append("[classification: " + getClassification() + "]\n");
    sb.append("[source: " + getSource() + "]\n");
    sb.append("[target: " + getTarget() + "]\n");
    sb.append("[reason: " + getReason() + "]\n");
    sb.append("[data: " + getData() + "]\n");
    return sb.toString();
  }
}