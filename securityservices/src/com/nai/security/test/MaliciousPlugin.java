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

import java.io.*;
import java.net.*;
import java.lang.*;
import java.text.DateFormat;
import java.util.Date;
import java.util.Iterator;

import org.cougaar.core.plugin.SimplePlugin;

public class MaliciousPlugin extends SimplePlugin
{
   public MaliciousPlugin() {}

    protected void setupSubscriptions() {
      // Attempts to read a file for which we should not
      // have access
      String fileName = "/etc/passwd";
      try {
	FileReader f = new FileReader(fileName);
	
	char[] cbuf = new char[2048];
	int nbcar = f.read(cbuf, 0, 2048);
	f.close();
      } catch (Exception e) {
	e.printStackTrace();
      }
    }

    public void execute() {}

}
