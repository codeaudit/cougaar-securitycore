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

package com.nai.security.crypto;

import java.io.*;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.Vector;
import java.util.Properties;

import java.security.*;
import java.security.cert.*;

/** A common holder for Security keystore information and functionality
    This class may be access by entities outside the crypto package.
    It should be implemented as a service when the appropriate service
    broker functionality will be available.
 **/

public class PublicKeyRing {
  
  static java.security.cert.Certificate getCert(String name) {
    return KeyRing.getCert(name);
  }

  public static  void setSleeptime(long sleeptime)
  {
    KeyRing.setSleeptime(sleeptime);
  }
  public static long getSleeptime()
  {
    return KeyRing.getSleeptime();
  }

  public static Vector getCRL() {
    return KeyRing.getCRL();
  }
}
    
