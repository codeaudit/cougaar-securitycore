/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package test.org.cougaar.core.security.simul;

import java.io.*;
import java.util.*;
import java.util.regex.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import junit.framework.*;

import org.w3c.dom.*;

public class Experiment
{
  private String experimentName;
  private Vector nodeConfList;
  private OperationConf preOperation;
  private OperationConf postOperation;
 

  public Experiment() {
    nodeConfList = new Vector();
  }

  public void setExperimentName(String name) {
    experimentName = name;
  }
    
  public void addNodeConfiguration(NodeConfiguration nc) {
    nodeConfList.addElement(nc);
  }
  public Vector getNodeConfiguration() {
    return nodeConfList;
  }

  public void setPreOperation(OperationConf oc) {
    preOperation = oc;
  }
  public OperationConf getPreOperation() {
    return preOperation;
  }

  public void setPostOperation(OperationConf oc) {
    postOperation = oc;
  }
  public OperationConf getPostOperation() {
    return postOperation;
  }

  public String toString() {
    String s = "Experiment name: " + experimentName + "\n";

    s = s + ( (preOperation == null) ? "None" : preOperation.toString()) + "\n";
    s = s + ( (postOperation == null) ? "None" : postOperation.toString()) + "\n";

    Enumeration e = nodeConfList.elements();
    int i = 0;
    while (e.hasMoreElements()) {
      NodeConfiguration nc = (NodeConfiguration) e.nextElement();
      s = s + "=====================\n" +
	"Node Configuration " + i + "\n"
	+ nc.toString();
      i++;
    }

    return s;
  }
}
