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
  public final static String INVALID_CERTIFICATE = "Invalid Certificate";
  public final static String SIGN_AND_ENCRYPT_FAILURE = "Sign and Encrypt Failure";
  public final static String DECRYPT_AND_VERIFY_FAILURE = "Decrypt and Verify Failure";
  public final static String IO_EXCEPTION = "IO Exception";
  public final static String UNKNOWN_FAILURE = "Unknown Failure";
  
  public CryptoFailureEvent(String classification, String source, String target, 
    String reason, String reasonId, String data, String dataId){
    super(classification, source, target, reason, reasonId, data, dataId);
  }
}
