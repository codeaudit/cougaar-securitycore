/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 * Created on September 12, 2001, 10:55 AM
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
    boolean enc = (_policy.secureMethod == SecureMethodParam.ENCRYPT ||
                   _policy.secureMethod == SecureMethodParam.SIGNENCRYPT);
    boolean sign = (_policy.secureMethod == SecureMethodParam.SIGN ||
                   _policy.secureMethod == SecureMethodParam.SIGNENCRYPT);
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
