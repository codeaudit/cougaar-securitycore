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

import javax.swing.JEditorPane;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JFrame;
import java.awt.*;
import java.awt.event.*;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.event.TreeSelectionListener;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.tree.TreeSelectionModel;
import javax.swing.tree.TreeNode;
import java.net.URL;
import java.io.IOException;

/**
 * This class contains various protocol hierarchy statistics.
 */
public class ProtocolHierarchyFrame
  extends JFrame
{
  private TreeNode _top;
  private JEditorPane _detailPane;
  private URL _helpURL;

  //Optionally play with line styles.  Possible values are
  //"Angled", "Horizontal", and "None" (the default).
  private boolean _playWithLineStyle = false;
  private String _lineStyle = "Angled"; 

  public ProtocolHierarchyFrame(TreeNode top) {
    super("ProtocolHierarchyFrame");

    //Create the nodes.
    _top = top;

    //Create a tree that allows one selection at a time.
    final JTree tree = new JTree(_top);
    tree.getSelectionModel().setSelectionMode
      (TreeSelectionModel.SINGLE_TREE_SELECTION);

    //Listen for when the selection changes.
    tree.addTreeSelectionListener(new TreeSelectionListener() {
	public void valueChanged(TreeSelectionEvent e) {
	  DefaultMutableTreeNode node = (DefaultMutableTreeNode)
	    tree.getLastSelectedPathComponent();

	  if (node == null) return;

	  Object nodeInfo = node.getUserObject();
	  ProtocolStatistics ps = (ProtocolStatistics)nodeInfo;
	  displayStats(ps);
	}
      });

    if (_playWithLineStyle) {
      tree.putClientProperty("JTree.lineStyle", _lineStyle);
    }

    //Create the scroll pane and add the tree to it. 
    JScrollPane treeView = new JScrollPane(tree);

    //Create the HTML viewing pane.
    _detailPane = new JEditorPane();
    _detailPane.setEditable(false);
    JScrollPane detailView = new JScrollPane(_detailPane);

    //Add the scroll panes to a split pane.
    JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    splitPane.setTopComponent(treeView);
    splitPane.setBottomComponent(detailView);

    Dimension minimumSize = new Dimension(300, 80);
    detailView.setPreferredSize(minimumSize);
    minimumSize = new Dimension(300, 300);
    treeView.setPreferredSize(minimumSize);
    splitPane.setDividerLocation(-1); //XXX: ignored in some releases
    //of Swing. bug 4101306
    //workaround for bug 4101306:
    //treeView.setPreferredSize(new Dimension(100, 100)); 

    //splitPane.setPreferredSize(new Dimension(500, 300));

    //Add the split pane to this frame.
    getContentPane().add(splitPane, BorderLayout.CENTER);
  }

  private void displayStats(ProtocolStatistics ps) {
    _detailPane.setText(ps.getDetails());
  }

  public void displayFrame() {
    addWindowListener(new WindowAdapter() {
	public void windowClosing(WindowEvent e) {
	  System.exit(0);
	}
      });  
    
    pack();
    setVisible(true);
  }
}
