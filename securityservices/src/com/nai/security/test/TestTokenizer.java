/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */

package com.nai.security.test;

import java.util.*;
import java.util.StringTokenizer;

public class TestTokenizer {
  public static void main(String args[]) {
    System.out.println("TestJaas main()");
    TestTokenizer t = new TestTokenizer();
    String spec = "";
    if (args.length > 0) {
      spec = args[0];
    }
    String st = t.normalizeCipherSpec(spec);
    System.out.println("spec=" + st);
  }

  private String normalizeCipherSpec(String spec) {
    String newSpec = "";
    StringTokenizer st = new StringTokenizer(spec, "/");
    int count = 0;
    while (st.hasMoreTokens()) {
      String next = st.nextToken();
      newSpec = newSpec + next;
      if (count < 2) {
	newSpec = newSpec + "/";
      }
      count++;
    }
    switch (count) {
    case 0:
      // No algorithm was provided. Use default parameters
      newSpec = "DESede/ECB/PKCS#1";
      break;
    case 1:
      // Neither the cipher nor the padding algorithm were specified.
      // Some providers require this to be specified.
      // Add default parameters.
      newSpec = newSpec + "ECB/PKCS#1";
      break;
    case 2:
      // The padding algorithm was not specified.
      // Some providers require this to be specified.
      // Add default parameters.
      newSpec = newSpec + "PKCS#1";
      break;
    case 3:
      // All the parameters were specified.
      break;
    default:
      // Problem in the specification.
      // Use default parameters.
      newSpec = "DESede/ECB/PKCS#1";
      break;
    }
    return newSpec;
  }
}
