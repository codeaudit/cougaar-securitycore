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

import java.util.Map;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import org.cougaar.security.mop.swing.*;

public class EtherealHierarchyParser
{
  private BufferedReader _reader;
  private Logger _log;
  private TreeNode _protocolHierarchyTree;
  private Map _protocolPolicy;
  private GlobalStatistics _statistics = new GlobalStatistics();

  private final static String ANALYSIS_HEADER =
  "Protocol Hierarchy Statistics";
  private final static String ANALYSIS_TRAILER =
  "===========================";

  private boolean _displayUI = false;
  private String _logFileName = null;

  private void parseArguments(String args[]) {
    for (int i = 0 ; i < args.length ; i++) {
      if (args[i].equals("-ui")) {
	_displayUI = true;
      }
      else if (args[i].startsWith("-h")) {
	printUsage();
	System.exit(0);
      }
    }
    if (args.length == 0) {
      printUsage();
      System.exit(0);
    }
    _logFileName = args[args.length - 1];
  }

  private void printUsage() {
    System.out.println("Usage: "
      + getClass().getName() + " [-ui] filename");
    System.out.println("-ui: display a UI with various statistics");
    System.out.println("     otherwise, dump global results on STDOUT");
    System.out.println("filename: network capture file parsed with the analyze script");
  }

  public static void main(String args[]) {
    try {
      CryptoConfigParser pp = new CryptoConfigParser();
      pp.parseConfigFile(null);

      EtherealHierarchyParser ep = new EtherealHierarchyParser();
      ep.parseArguments(args);
      ep.setProtocolPolicy(pp.getProtocolPolicy());
      ep.parseResults();
      if (ep._displayUI) {
	ep.displayProtocolHierarchy();
      }
      else {
	// display global statistics on stdout
	System.out.println(ep._statistics.toHtml());
      }
    }
    catch (Exception e) {
      System.out.println("Exception while processing data: " + e);
    }
  }

  private void setProtocolPolicy(Map map) { _protocolPolicy = map; }

  private void displayProtocolHierarchy() { 
    ProtocolHierarchyFrame ph =
      new ProtocolHierarchyFrame(_protocolHierarchyTree);
    ph.displayGlobalStatistics(_statistics);
    ph.displayFrame();
 }

  public EtherealHierarchyParser() {
    _log = LoggerFactory.getInstance().createLogger(this);
  }

  public void parseResults() {
    try {
      _reader = new BufferedReader(new FileReader(_logFileName));
    }
    catch (IOException e) {
      _log.warn("Unable to read file:" + _logFileName);
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
	Long frames = Long.decode(matcher.group(5));
	Long bytes = Long.decode(matcher.group(8));
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
	  _statistics.setTotalBytes(bytes.longValue());
	  _statistics.setTotalFrames(frames.longValue());
	}
	else {
	  // Insert node in the tree
	  if (treeLevel > previousTreeLevel) {
	    currentNode.add(newNode);
	    updateProtocolStatistics(currentNode, newNode);
	  }
	  else if (treeLevel == previousTreeLevel) {
	    DefaultMutableTreeNode parent = ((DefaultMutableTreeNode)currentNode.getParent());
	    parent.add(newNode);
	    updateProtocolStatistics(parent, newNode);
	  }
	  else {
	    // Move up
	    for (int i = 0 ; i <= (previousTreeLevel - treeLevel) ; i++) {
	      currentNode = (DefaultMutableTreeNode)currentNode.getParent();
	    }
	    currentNode.add(newNode);
	    updateProtocolStatistics(currentNode, newNode);
	  }
	  currentNode = newNode;
	  previousTreeLevel = treeLevel;
	}

	// Build the protocol chain up to the root.
	StringBuffer sb = new StringBuffer();
	sb.append(ps.getProtocolName());
	TreeNode tn = newNode;
	while ((tn = tn.getParent()) != null) {
	  ProtocolStatistics psParent = (ProtocolStatistics)
	    ((DefaultMutableTreeNode)tn).getUserObject();
	  sb.insert(0, ".");
	  sb.insert(0, psParent.getProtocolName());
	}
	ps.setProtocolPath(sb.toString());
	_log.debug("Path:" + ps.getProtocolPath());
	ProtocolPolicy pp = (ProtocolPolicy) _protocolPolicy.get(ps.getProtocolPath());
	if (pp == null) {
	  // Create a default one
	  pp = new ProtocolPolicy(ps.getProtocolPath(), null, null);
	}
	ps.setProtocolPolicy(pp);
      }
      _reader.close();
    }
    catch (IOException e) {
      _log.warn("Unable to read file:" + _logFileName);
    }

    Enumeration enum =
      ((DefaultMutableTreeNode)_protocolHierarchyTree).breadthFirstEnumeration();
    while (enum.hasMoreElements()) {
      ProtocolStatistics ps = (ProtocolStatistics)
	((DefaultMutableTreeNode)enum.nextElement()).getUserObject();
      long bytes = ps.getBytes().longValue();
      long frames = ps.getFrames().longValue();
      if (ps.getProtocolPolicy().isEncrypted() == Boolean.TRUE) {
	_statistics.setTotalEncryptedBytes(_statistics.getTotalEncryptedBytes() + bytes);
	_statistics.setTotalEncryptedFrames(_statistics.getTotalEncryptedFrames() + frames);
      }
      else {
	_statistics.setTotalUnencryptedBytes(_statistics.getTotalUnencryptedBytes() + bytes);
	_statistics.setTotalUnencryptedFrames(_statistics.getTotalUnencryptedFrames() + frames);
      }
      if (ps.getProtocolPolicy().isOk() == Boolean.FALSE ||
	  ps.getProtocolPolicy().isOk() == null) {
	if (ps.getProtocolPolicy().isEncrypted() == Boolean.TRUE) {
	  // This should not happen.
	  _log.error("Protocol marked as encrypted and policy says it's not OK");
	}
	_statistics.setTotalUnexpectedUnencryptedBytes(
	  _statistics.getTotalUnexpectedUnencryptedBytes() + bytes);
	_statistics.setTotalUnexpectedUnencryptedFrames(
	  _statistics.getTotalUnexpectedUnencryptedFrames() + frames);
      }
    }
  }

  private void updateProtocolStatistics(DefaultMutableTreeNode parent,
					DefaultMutableTreeNode node) {
    ProtocolStatistics parentStat = (ProtocolStatistics)parent.getUserObject();
    ProtocolStatistics nodeStat = (ProtocolStatistics)node.getUserObject();

    _log.debug("Updating stats: " + parentStat.getProtocolName()
      + " - " + nodeStat.getProtocolName());
    Long bytes = new Long(parentStat.getBytes().longValue() - nodeStat.getBytes().longValue());
    Long frames = new Long(parentStat.getFrames().longValue() - nodeStat.getFrames().longValue());
    parentStat.setBytes(bytes);
    parentStat.setFrames(frames);
  }
					
}
