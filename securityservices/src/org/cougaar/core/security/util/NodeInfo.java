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

package org.cougaar.core.security.util;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.node.NodeIdentificationService;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.StringTokenizer;

public class NodeInfo
{
  private static String nodeName = null;
  private static String hostName = null;

  /** Returns the name of the node. Deals with backward compatibility issues */
  public static String getNodeName()
  {
    if (nodeName != null)
      return nodeName;

    int major = 0;
    int minor = 0;
    String version = null;
    try {
      Class vc = Class.forName("org.cougaar.Version");
      Field vf = vc.getField("version");
      version = (String) vf.get(null);
    } catch (Exception e) {}

    StringTokenizer st = new StringTokenizer(version, ".");
    for (int i = 0 ; st.hasMoreTokens() ; i++) {
      String s = st.nextToken();
      switch (i) {
      case 0:
	major = Integer.valueOf(s).intValue();
	break;
      case 1:
	minor = Integer.valueOf(s).intValue();
	break;
      default:
      }
    }
    // Cougaar 8.4: node name is in org.cougaar.core.society.Node.name
    // Cougaar >=8.6: node name is in org.cougaar.node.name

    if (major <= 8 && minor <=4) {
      nodeName = System.getProperty("org.cougaar.core.society.Node.name");
    }
    else {
      nodeName = System.getProperty("org.cougaar.node.name");
    }
    //System.out.println("Version: " + major + "." + minor + " - Node name:" + nodeName);
    return nodeName;
  }

  public void setNodeName(ServiceBroker sb) {
    NodeIdentificationService nis = (NodeIdentificationService)
      sb.getService(this, NodeIdentificationService.class, null);
    nodeName = nis.getMessageAddress().toString();
  }

  public static String getHostName() {
    if (hostName == null) {
      // is it set in a system parameter?
      hostName = System.getProperty("org.cougaar.core.security.hostname");
      if (hostName != null && !hostName.equals("")) {
        return hostName;
      }
      try {
        hostName = InetAddress.getLocalHost().getHostName();
      } catch (UnknownHostException ex) {
	System.err.println("Unable to get my host name: " + ex.toString());
      }
    }
    return hostName;
  }


}
