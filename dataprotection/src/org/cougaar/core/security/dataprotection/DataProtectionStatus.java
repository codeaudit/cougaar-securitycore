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


package org.cougaar.core.security.dataprotection;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

public class DataProtectionStatus {
  public static final String INPUT_COMPLETE = "INPUT_COMPLETE";
  public static final String OUTPUT_COMPLETE = "OUTPUT_COMPLETE";
  public static final String RECOVERY_REQUEST = "RECOVERY_REQUEST";
  public static final String KEY_RECOVERED = "KEY_RECOVERED";

  public long timestamp;
  public String agent;
  public String status;

  private static Hashtable inputStatus = new Hashtable();
  private static Hashtable outputStatus = new Hashtable();

  public DataProtectionStatus(long timestamp, String agent, String status) {
    this.timestamp = timestamp;
    this.agent = agent;
    this.status = status;
  }

  public static void addInputStatus(String agent, String status) {
    addStatus(inputStatus, agent, status);
  }

  public static void addOutputStatus(String agent, String status) {
    addStatus(outputStatus, agent, status);
  }

  public static Hashtable getInputStatus() {
    return inputStatus;
  }

  public static Hashtable getOutputStatus() {
    return outputStatus;
  }

  private static void addStatus(Hashtable t, String agent, String status) {
    // add status only after servlet init status
    // prevents test case to affect the normal operations and consume memory
    // if this is not setup to run test cases
    if (t == null) {
      return;
    }

    List l = (List)t.get(agent);
    if (l == null) {
      l = new ArrayList();
      t.put(agent, l);
    }
    long time = System.currentTimeMillis();
    l.add(new DataProtectionStatus(time, agent, status));

    // only keep half 30 minutes log by default
    DataProtectionStatus s = (DataProtectionStatus)l.get(0);
    long elapse = s.timestamp - time;
    if (elapse > 30 * 60 * 1000) {
      l.remove(0);
    }
  }
}
