/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


package org.cougaar.core.security.cm;


import java.io.Serializable;


/**
 * DOCUMENT ME!
 *
 * @version $Revision: 1.1 $
 * @author $author$
 */
public class NodeConfiguration implements Serializable {
  private String nodeName;
  private String nodeType;

  /**
   * Creates a new NodeConfiguration object.
   *
   * @param name DOCUMENT ME!
   * @param type DOCUMENT ME!
   */
  public NodeConfiguration(String name, String type) {
    this.nodeName = name;
    this.nodeType = type;
  }

  /**
   * DOCUMENT ME!
   *
   * @return
   */
  public String getNodeName() {
    return nodeName;
  }


  /**
   * DOCUMENT ME!
   *
   * @param nodeName
   */
  public void setNodeName(String nodeName) {
    this.nodeName = nodeName;
  }


  /**
   * DOCUMENT ME!
   *
   * @return
   */
  public String getNodeType() {
    return nodeType;
  }


  /**
   * DOCUMENT ME!
   *
   * @param nodeType
   */
  public void setNodeType(String nodeType) {
    this.nodeType = nodeType;
  }
}
