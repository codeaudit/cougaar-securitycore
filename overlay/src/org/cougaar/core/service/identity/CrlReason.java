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
 *
 * Created on September 12, 2001, 10:55 AM
 */


package org.cougaar.core.service.identity;

public class CrlReason
{
  // revocation reasons:
  public static int UNSPECIFIED            = 0;
  public static int KEY_COMPROMISE         = 1;
  public static int CA_COMPROMISE          = 2;
  public static int AFFILIATION_CHANGED    = 3;
  public static int SUPERSEDED             = 4;
  public static int CESSATION_OF_OPERATION = 5;
  public static int CERTIFICATE_HOLD       = 6;
  public static int REMOVE_FROM_CRL        = 8;
  public static int PRIVILEGE_WITHDRAWN    = 9;
  public static int AA_COMPROMISE          = 10;

  private int reason;

  // private constructor, called only within this class
  public CrlReason(int value) {
    reason = value;
  }

  public int getReason() {
    return reason;
  }
}
