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

package org.cougaar.core.security.test;

import java.io.Serializable;
import java.security.*;
import java.util.HashMap;
import java.util.*;
import javax.naming.Context;
import org.cougaar.core.security.bootstrap.SystemProperties;

public class TestProperties {
        
  public static void main(String[] args) {
    Properties props = System.getProperties();

    System.out.println("Context: " + Context.INITIAL_CONTEXT_FACTORY);
  
    props.list(System.out);
    
    System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++");
    /*
    for (Enumeration names = props.propertyNames(); names.hasMoreElements(); ) {
      String key = (String) names.nextElement();
      System.out.println("key:" + key);
    }
    */
    System.out.println("Props +++++++++++++++++++++++++++++++++++++++++++++++++++");
    props = SystemProperties.getStandardSystemProperties();
    System.out.println("Props +++++++++++++++++++++++++++++++++++++++++++++++++++");
    props.list(System.out);


    System.out.println("Props with prefix org.cougaar ++++++++++++++++++++++++++++");
    props = SystemProperties.getSystemPropertiesWithPrefix("org.cougaar");

    System.out.println("Props with prefix sun +++++++++++++++++++++++++++++++++++");
    props = SystemProperties.getSystemPropertiesWithPrefix("sun.");
  }
}
