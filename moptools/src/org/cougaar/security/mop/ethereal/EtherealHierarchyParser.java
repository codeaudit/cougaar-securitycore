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

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class EtherealHierarchyParser
{
  private BufferedReader _reader;
  private Logger _log;
  private TreeNode _protocolHierarchyTree;

  private final static String ANALYSIS_HEADER =
  "Protocol Hierarchy Statistics";
  private final static String ANALYSIS_TRAILER =
  "===========================";

  public static void main(String args[]) {
    EtherealHierarchyParser ep = new EtherealHierarchyParser();
    ep.parseResults(args[0]);
    ep.displayProtocolHierarchy();
  }

  private void displayProtocolHierarchy() { 
    ProtocolHierarchyFrame ph =
      new ProtocolHierarchyFrame(_protocolHierarchyTree);
    ph.displayFrame();
 }

  public EtherealHierarchyParser() {
    _log = LoggerFactory.getInstance().createLogger(this);
  }

  public void parseResults(String filename) {
    try {
      _reader = new BufferedReader(new FileReader(filename));
    }
    catch (IOException e) {
      _log.warn("Unable to read file:" + filename);
    }
    String line = null;
    boolean skipLines = true;

    Pattern pattern = Pattern.
      compile("(\\s*)(\\S*)(\\s*)(frames:)(\\d*)(\\s*)(bytes:)(\\d*)(\\s*)");
    Matcher matcher = null;

    try {
      DefaultMutableTreeNode currentNode = null;
      int previousTreeLevel = 0;
      while ( (line = _reader.readLine()) != null ) {
	// Skip packet summary
	if (skipLines) {
	  if (!line.startsWith(ANALYSIS_HEADER)) {
	    continue;
	  }
	  else {
	    skipLines = false;
	    _reader.readLine(); // Read "Filter: " line
	    _reader.readLine(); // Read empty line
	    line = _reader.readLine();
	  }
	}
	if (line.startsWith(ANALYSIS_TRAILER)) {
	  break;
	}
	matcher = pattern.matcher(line);
	boolean match = matcher.find();
	if (!match) {
	  if (_log.isWarnEnabled()) {
	    _log.warn("Unable to find expected pattern at line: " + line);
	  }
	  continue; // Line does not match pattern
	}

	// There are two white space characters per level
	int treeLevel = matcher.start(2) / 2;

	String protocolName = matcher.group(2);
	long frames = Long.parseLong(matcher.group(5));
	long bytes = Long.parseLong(matcher.group(8));
	if (_log.isDebugEnabled()) {
	  _log.debug("treeLevel: " + treeLevel + " - previous: " +
		     previousTreeLevel + " - Protocol: " + protocolName
	    + " - Frames: " + frames + " - Bytes: " + bytes);
	}
	ProtocolStatistics ps =
	  new ProtocolStatistics(protocolName, frames, bytes);
	DefaultMutableTreeNode newNode =
	  new DefaultMutableTreeNode(ps);
	if (treeLevel == 0) {
	  _protocolHierarchyTree = newNode;
	  currentNode = newNode;
	}
	else {
	  // Insert node in the tree
	  if (treeLevel > previousTreeLevel) {
	    currentNode.add(newNode);
	  }
	  else if (treeLevel == previousTreeLevel) {
	    ((DefaultMutableTreeNode)currentNode.getParent()).
	      add(newNode);
	  }
	  else {
	    // Move up
	    for (int i = 0 ; i <= (previousTreeLevel - treeLevel) ; i++) {
	      currentNode = (DefaultMutableTreeNode)currentNode.getParent();
	    }
	    currentNode.add(newNode);
	  }
	  currentNode = newNode;
	  previousTreeLevel = treeLevel;
	}
      }
      _reader.close();
    }
    catch (IOException e) {
      _log.warn("Unable to read file:" + filename);
    }
  }

}
