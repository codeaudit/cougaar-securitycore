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

package org.cougaar.security.mop.ethereal;

import javax.swing.tree.TreeNode;
import javax.swing.tree.DefaultMutableTreeNode;

import org.cougaar.security.mop.treemodel.AbstractTreeTableModel;
import org.cougaar.security.mop.treemodel.TreeTableModel;

/**
 * This class contains various statistics about a network protocol.
 */
public class ProtocolStatisticsTreeModel
  extends AbstractTreeTableModel 
  implements TreeTableModel
{

  // Names of the columns.
  static protected String[]  cNames = {"Name", "Total Frames", "Frames",
				       "Total Bytes", "Bytes",
				       "Protection", "Status"};

  // Types of the columns.
  static protected Class[]  cTypes = {TreeTableModel.class, Long.class, Long.class,
				      Long.class, Long.class,
				      Boolean.class, Boolean.class};

  public ProtocolStatisticsTreeModel(TreeNode rootNode) {
    super(rootNode);
  }


  //
  // Some convenience methods. 
  //

  protected ProtocolStatistics getProtocolStatistics(Object node) {
    return (ProtocolStatistics)
      ((DefaultMutableTreeNode)node).getUserObject(); 
  }

  //
  // The TreeModel interface
  //

  public int getChildCount(Object node) { 
    return ((TreeNode)node).getChildCount();
  }

  public Object getChild(Object node, int i) {
    return ((TreeNode)node).getChildAt(i);
  }

  
  //
  //  The TreeTableNode interface. 
  //

  public int getColumnCount() {
    return cNames.length;
  }

  public String getColumnName(int column) {
    return cNames[column];
  }

  public Class getColumnClass(int column) {
    return cTypes[column];
  }
 
  public Object getValueAt(Object node, int column) {
    ProtocolStatistics stats = getProtocolStatistics(node); 
    switch(column) {
    case 0:
      return stats.getProtocolName();
    case 1:
      return stats.getTotalFrames();
    case 2:
      return stats.getFrames();
    case 3:
      return stats.getTotalBytes();
    case 4:
      return stats.getBytes();
    case 5:
      return stats.getProtocolPolicy().isEncrypted();
    case 6:
      return stats.getProtocolPolicy().isOk();
    }
    return null; 
  }
}
