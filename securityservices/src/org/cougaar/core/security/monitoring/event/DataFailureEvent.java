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
 * This data structure represent a Data Protection  Failure Event that could
 * occur during data persistence.
 */
public class DataFailureEvent extends CryptoFailureEvent {
  public final static String REASON_ID = "DATA_FAILURE_REASON";
  public final static String DATA_ID = "DATA_FAILURE_DATA";
  //reasons
  public final static String NO_PRIVATE_KEYS = "No private keys";
  public final static String NO_CERTIFICATES = "No certificates";
  public final static String CREATE_KEY_FAILURE = "Failed to create key";
  public final static String NO_KEYS = "No data protection keys";
  public final static String VERIFY_DIGEST_FAILURE = "Verify digest failure";
  public final static String CLASS_NOT_FOUND = "Class not found";
  public final static String SECRET_KEY_FAILURE = "Unable to get secret key";
  
  public DataFailureEvent(String source, String target, String reason, String data){
    super(IdmefClassifications.DATA_FAILURE, source, 
      target, reason, REASON_ID, data, DATA_ID);
  }
}
