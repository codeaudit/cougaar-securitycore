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

import java.io.Serializable;

public class NodeConfiguration
  implements Serializable
{
  /** The top-level directory of the securityservices module.
   */
  private String topLevelDirectory;

  /** The startup directory for the node.
   */
  private String nodeDirectoryName;

  /** The file containing the java properties for the node.
   */
  private String propertyFile;

  /** The command-line arguments when starting the node.
   */
  private String arguments[];

  /** The host name where the node is executed.
   */
  private String hostName;

  /** The maximum amount of time (in seconds) during which the node can run.
   */
  private int maxExecutionTime;

  /** The waiting period (in seconds) before the node is executed.
   */
  private int howLongBeforeStart;

  /** The HTTP port number of the node's web server.
   */
  private int httpPort;

  /** The HTTPS port number of the node's web server.
   */
  private int httpsPort;

  /** The RMI registry port number of the node's server.
   */
  private int rmiRegistryPort;

  public NodeConfiguration() {
  }

  // GET methods
  public String getTopLevelDirectory() {
    return topLevelDirectory;
  }
  public String getNodeStartupDirectoryName() {
    return nodeDirectoryName;
  }
  public String getPropertyFile() {
    return propertyFile;
  }
  public String[] getArguments() {
    return arguments;
  }
  public int getMaxExecutionTime() {
    return maxExecutionTime;
  }
  public int getHowLongBeforeStart() {
    return howLongBeforeStart;
  }
  public String getHostName() {
    return hostName;
  }
  public int getHttpPort() {
    return httpPort;
  }
  public int getHttpsPort() {
    return httpsPort;
  }
  public int getRmiRegistryPort() {
    return rmiRegistryPort;
  }

  // SET methods
  public void setTopLevelDirectory(String dir) {
    topLevelDirectory = dir;
  }
  public void setNodeStartupDirectoryName(String dir) {
    nodeDirectoryName = dir;
  }
  public void setPropertyFile(String file) {
    propertyFile = file;
  }
  public void setArguments(String args[]) {
    arguments = args;
  }
  public void setMaxExecutionTime(int max) {
    maxExecutionTime = max;
  }
  public void setHowLongBeforeStart(int howlong) {
    howLongBeforeStart = howlong;
  }
  public void setHostName(String host) {
    hostName = host;
  }
  public void setHttpPort(int port) {
    httpPort = port;
  }
  public void setHttpsPort(int port) {
    httpsPort = port;
  }
  public void setRmiRegistryPort(int port) {
    rmiRegistryPort = port;
  }
}
