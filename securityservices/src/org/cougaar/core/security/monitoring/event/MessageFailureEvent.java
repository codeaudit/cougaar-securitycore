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

// Cougaar overlay
import org.cougaar.core.security.constants.IdmefClassifications;

/**
 * This data structure represent an Message Failure Event
 */
public class MessageFailureEvent extends CryptoFailureEvent {
  public final static String REASON_ID = "MESSAGE_FAILURE_REASON";
  public final static String DATA_ID = "MESSAGE_FAILURE_DATA";
  // reasons
  public final static String INCONSISTENT_IDENTIFIER = "Inconsistent Identifier";
  public final static String SETASIDE_INCOMING_MESSAGE_ACTION = "Set Aside Incoming Message Action";
  public final static String SETASIDE_OUTGOING_MESSAGE_ACTION = "Set Aside Outgoing Message Action";
  public final static String SETASIDE_INCOMING_AGENT_ACTION = "Set Aside Incoming Agent Action";
  public final static String SETASIDE_OUTGOING_AGENT_ACTION = "Set Aside Outgoing Agent Action";
  public final static String INVALID_MESSAGE_CONTENTS = "Invalid Message Contents";
  public final static String SOURCE_ADDRESS_MISMATCH = "Source Address Mismatch";
  public final static String VERB_DENIED = "Verb Denied";
  public final static String INVALID_COMMUNITY_REQUEST = "Invalid Community Request";
  
  public MessageFailureEvent(String source, String target, String reason, String data){
    super(IdmefClassifications.MESSAGE_FAILURE, source, 
      target, reason, REASON_ID, data, DATA_ID);
  }
}
