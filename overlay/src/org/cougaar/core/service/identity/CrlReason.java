/*
 * <copyright>
 *  Copyright 1997-2002 Networks Associates Technology, Inc.
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

/**
 * Reasons for revoking a certificate.
 */
public class CrlReason
{
  // revocation reasons:
  public static final int UNSPECIFIED            = 0;
  public static final int KEY_COMPROMISE         = 1;
  public static final int CA_COMPROMISE          = 2;
  public static final int AFFILIATION_CHANGED    = 3;
  public static final int SUPERSEDED             = 4;
  public static final int CESSATION_OF_OPERATION = 5;
  public static final int CERTIFICATE_HOLD       = 6;
  public static final int REMOVE_FROM_CRL        = 8;
  public static final int PRIVILEGE_WITHDRAWN    = 9;
  public static final int AA_COMPROMISE          = 10;

  private int reason;

  // private constructor, called only within this class
  public CrlReason(int value) {
    reason = value;
  }

  public int getReason() {
    return reason;
  }
}
