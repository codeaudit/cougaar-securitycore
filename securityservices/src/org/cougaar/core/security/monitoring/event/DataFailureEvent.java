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
