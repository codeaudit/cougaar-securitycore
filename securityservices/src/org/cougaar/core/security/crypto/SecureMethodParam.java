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

  public String toString() {
    return "SecureMethodParam: " + getSecureMethodToString() + ' ' +
      symmSpec + ' ' + asymmSpec + ' ' + signSpec;
  }
}
