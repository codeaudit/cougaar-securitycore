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


package org.cougaar.core.security.crypto;

import java.io.Serializable;

public final class SecureMethodParam
  implements Serializable
{

  public static final int PLAIN = 1;
  public static final int SIGN = 2;
  public static final int ENCRYPT = 3;
  public static final int SIGNENCRYPT = 4;
  public static final int INVALID = 5;

  public static final String SECURE_METHODS[] = {
    "INVALID", "PLAIN", "SIGN", "ENCRYPT", "SIGNENCRYPT" };

  public int secureMethod;
  public String symmSpec;
  public String asymmSpec;
  public String signSpec;
  // public String providerName;
    
  public SecureMethodParam() {
    secureMethod = INVALID;
  }
  public SecureMethodParam(int value) {
    secureMethod = value;
  }

  public static String secureMethodToString(int method) {
    if (method < SECURE_METHODS.length && method >= 0) {
      return SECURE_METHODS[method];
    }
    return "UNKNOWN";
  }

  public String getSecureMethodToString() {
    return secureMethodToString(secureMethod);
  }

  /**
   * Print the SecureMethodParam as a string
   */
  public String toString() {
    /*
     * This routine prints the method of signing and encrypting the message 
     * even when the policy says that these algorithms don't need to be used. 
     * This makes other routines that copy this object and drop the extra
     * information look wrong even though they work correctly.  I think the 
     * "(ignorable)" logic will help the next guy debugging this code.  This
     * should probably be fixed. (e.g. make a real class that hides this 
     * stuff?) 
     */
    boolean enc = (secureMethod == SecureMethodParam.ENCRYPT ||
                   secureMethod == SecureMethodParam.SIGNENCRYPT);
    boolean sign = (secureMethod == SecureMethodParam.SIGN ||
                   secureMethod == SecureMethodParam.SIGNENCRYPT);
    String out = "SecureMethodParam: " + getSecureMethodToString();
    out += " " + symmSpec;
    if (!enc) {
      out += " (ignorable)";
    }
    out += " " + signSpec;
    if (!sign) {
      out += " (ignorable)";
    }
    return out;
  }

  /*
   * Maybe there should be readObject and writeObject routines here.  Look at 
   * ProtectedMessageHeader.java.
   */
}
