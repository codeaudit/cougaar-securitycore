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

package org.cougaar.core.security.test;

import java.util.Iterator;
import java.security.PrivilegedAction;
import java.security.AccessController;
import java.security.AccessControlContext;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import java.io.*;
import java.net.*;
import java.lang.*;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.EntityResolver;
import org.apache.xerces.parsers.DOMParser;

import org.cougaar.util.ConfigFinder;


public class XMLfileLoader {
  public static void main(String args[]) {
    System.out.println("XMLfileLoader main()");
    XMLfileLoader fl = new XMLfileLoader(args[0]);
  }

  public XMLfileLoader(String xmlFilename) {

    ConfigFinder configFinder = ConfigFinder.getInstance();
    File f = configFinder.locateFile(xmlFilename);
    if (f == null) {
      return;
    }
    String path = f.getPath();

    System.out.println("Path= " + path);

    Document doc = null;

    try {
      doc = configFinder.parseXMLConfigFile(path);
    }
    catch (java.io.IOException e) {
      System.out.println("IO exception");
    }
    
    if (doc == null) {
      System.out.println("Unable to parse XML file");
    }
    System.out.println("Doc " + doc);
  }
}
