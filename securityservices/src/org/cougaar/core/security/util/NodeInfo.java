/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.util;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.StringTokenizer;

public class NodeInfo
{
  private static String nodeName = null;
  private static String hostName = null;
  private static Logger _log;

  static {
    _log = LoggerFactory.getInstance().createLogger(NodeInfo.class);
  }

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

    if (version == null) {
      // Assume it is a recent version
      major = 11;
    }
    else {
      StringTokenizer st = new StringTokenizer(version, ".");
      for (int i = 0 ; st.hasMoreTokens() ; i++) {
        String s = st.nextToken();
        switch (i) {
        case 0:
	  major = Integer.valueOf(s).intValue();
  	  break;
        case 1:
          {
            if (_log.isDebugEnabled()) {
              _log.debug("Minor version = " + s);
            }
            String [] vparts = s.split("[^0-9]");
            minor = Integer.valueOf(vparts[0]).intValue();
            if (_log.isDebugEnabled()) {
              _log.debug("Minor (int) version = " + minor);
            }
          }
	  break;
        default:
        }
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

  /**
   * Returns the name of the local host.
   * Care must be taken when using the host name for certificates.
   * The host name is used to set the Common Name (CN) attribute
   * of the host X.509 certificate.
   * Most clients (e.g. browsers or agents using HTTPs) verify that
   * the host name matches the CN of the X.509 certificate.
   * Usually, clients perform a reverse lookup of the server IP address
   * using DNS. The returned host name is matched against the CN
   * in the X.509 certificate provided in the SSL handshake.
   * In a normal deployment, fully qualified domain names should be used.
   * However, there are scenarios when another name resolution service
   * is being used. For example, hosts could use NIS, NIS+, WINS,
   * or host files. Care must be taken that the client and the server
   * will see the same name.
   * Another example is load balancing, when an array of servers
   * serve the same externally visible DNS name, but they have
   * different names internally.
   * The org.cougaar.core.security.hostname property can be used
   * to override the host name.
   *
   * Issues:
   * - getCanonicalHostName() may return the textual representation
   *   of the IP address if a reverse DNS lookup fails.
   * - getHostName() may return the FQDN if there is a matching
   *   entry in DNS, not just the host name.
   */
  public static String getHostName() {
    if (hostName == null) {
      // is it set in a system parameter?
      hostName = System.getProperty("org.cougaar.core.security.hostname");
      if (hostName != null && !hostName.equals("")) {
        return hostName;
      }
      try {
        //hostName = InetAddress.getLocalHost().getCanonicalHostName();
        hostName = InetAddress.getLocalHost().getHostName();
      } catch (UnknownHostException ex) {
	System.err.println("Unable to get my host name: " + ex.toString());
      }
    }
    if (_log.isDebugEnabled()) {
      _log.debug("hostname:" + hostName);
    }
    return hostName;
  }


}
