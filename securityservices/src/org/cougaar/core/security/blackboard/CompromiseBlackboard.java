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
 



package org.cougaar.core.security.blackboard;


import java.io.Serializable;

import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;


/**
 * Object marking the compromise of the Blackboard
 *
 * @author ttschampel
 */
public class CompromiseBlackboard implements UniqueObject, Serializable {
  private UID uid;
  private long timestamp;

  /**
   * Get UID
   *
   * @return UID
   */
  public UID getUID() {
    return uid;
  }


  /**
   * set the UID
   *
   * @param arg0 UID
   */
  public void setUID(UID arg0) {
    uid = arg0;

  }


  /**
   * get Timestamp of the compromise
   *
   * @return Timestamp of the compromise
   */
  public long getTimestamp() {
    return timestamp;

  }


  /**
   * set Timestamp of the compromise
   *
   * @param l Timestamp of the compromise
   */
  public void setTimestamp(long l) {
    timestamp = l;
  }
}
