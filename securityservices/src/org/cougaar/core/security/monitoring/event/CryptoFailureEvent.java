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

/**
 * This data structure represent a Crypto Failure Event that could
 * occur during data persistence.
 */
public class CryptoFailureEvent extends FailureEvent {
  // add the reasons for the failures here
  public final static String INVALID_POLICY = "Invalid Policy";
  public final static String SIGNING_FAILURE = "Signing Failure";
  public final static String VERIFICATION_FAILURE = "Verification Failure";
  public final static String ENCRYPT_FAILURE = "Encryption Failure";
  public final static String DECRYPT_FAILURE = "Decryption Failure";
  public final static String SIGN_AND_ENCRYPT_FAILURE = "Sign and Encrypt Failure";
  public final static String DECRYPT_AND_VERIFY_FAILURE = "Decrypt and Verify Failure";
  public final static String IO_EXCEPTION = "IO Exception";
  public final static String UNKNOWN_FAILURE = "Unknown Failure";
  
  public CryptoFailureEvent(String classification, String source, String target, 
    String reason, String reasonId, String data, String dataId){
    super(classification, source, target, reason, reasonId, data, dataId);
  }
}
