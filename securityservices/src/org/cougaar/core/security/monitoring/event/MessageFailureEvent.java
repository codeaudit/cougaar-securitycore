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
