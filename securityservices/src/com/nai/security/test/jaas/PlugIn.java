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

package com.nai.security.test.jaas;

import java.util.Iterator;
import java.io.*;
import java.net.*;
import java.lang.*;

import com.nai.security.bootstrap.JaasClient;

public class PlugIn
  implements java.security.PrivilegedExceptionAction
{
  String name = null;

  public PlugIn(String plugInName) {
    name = plugInName;
  }

  public Object run() {
    // Attempts to read a file for which we should not
    // have access
    JaasClient.printPrincipals();
    try {
      String fileName = "/etc/passwd";
      FileReader f = new FileReader(fileName);
      
      char[] cbuf = new char[2048];
      int nbcar = f.read(cbuf, 0, 2048);
      f.close();
    }
    catch (java.io.FileNotFoundException e) {
      System.out.println("Error: " + e);
    }
    catch (java.io.IOException e) {
      System.out.println("Error: " + e);
    }
    return null;
  }
}
