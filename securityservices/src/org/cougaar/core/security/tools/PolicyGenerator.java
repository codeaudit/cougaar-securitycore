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

package org.cougaar.core.security.tools;

import java.io.*;
import java.util.*;
import java.io.*;

import org.w3c.dom.*;
import org.apache.xml.serialize.*;
import org.apache.xerces.parsers.*;
import org.xml.sax.InputSource;

import org.cougaar.core.service.LoggingService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class PolicyGenerator
{
  private String communityConfFile = null;
  private Hashtable communities = null;

  private String policiesFile = null;
  private Hashtable policies = null;

  private String outputfileprefix = null;
  private String templateFile = null;
  private boolean debug = false;

  private static Logger _log;

  //private final String incommingSecureMethod = "IncomingSecureMethod";
  //private final String outgoingSecureMethod = "OutgoingSecureMethod";

  static {
    _log = LoggerFactory.getInstance().createLogger("PolicyGenerator");
  }

  public PolicyGenerator()
  {
    communities = new Hashtable();
    policies = new Hashtable();
  }

  public void setCommunityConfigurationFileName(String aFilename)
  {
    communityConfFile = aFilename;
  }

  public void setPolicyFileName(String aFilename)
  {
    policiesFile = aFilename;
  }

  public void setOutputFilePrefix(String aPrefix)
  {
    outputfileprefix = aPrefix;
  }

  public void setPolicyTemplate(String aPolicyTemplate)
  {
    templateFile = aPolicyTemplate;
  }

  public void parseCommunityFile()
  {
    parseFile(communityConfFile, communities);

    if (debug) {
      _log.debug("======== Configuration file:");
      printConfiguration();
      _log.debug("============================");
    }
  }

  public void parsePolicyFile()
  {
    parseFile(policiesFile, policies);
  }

  private void parseFile(String filename, Hashtable hashtable)
  {
    FileInputStream in = null;
    try {
      in = new FileInputStream(filename);
    }
    catch (Exception e) {
      e.printStackTrace();
      return;
    }
    Reader r = new BufferedReader(new InputStreamReader(in));
    StreamTokenizer st = new StreamTokenizer(r);

    st.resetSyntax();
    st.eolIsSignificant(true);
    st.wordChars('a', 'z');
    st.wordChars('A', 'Z');
    st.wordChars('!', '@');
    st.wordChars(128 + 32, 255);
    st.whitespaceChars(0, ' ');
    st.commentChar('/');
    st.commentChar('#');
    st.quoteChar('"');
    st.quoteChar('\'');


    int index = 0;
    ArrayList list = null;
    String key = null;

    try {
      while(st.nextToken() != StreamTokenizer.TT_EOF) {
	switch (st.ttype) {
	case StreamTokenizer.TT_EOL:
	  index = 0;
	  break;
	case StreamTokenizer.TT_WORD:
	  if (index == 0) {
	    // Read key name
	    key = st.sval;
	    list = (ArrayList) hashtable.get(key);
	    if (list == null) {
	      list = new ArrayList();
	    }
	  }
	  else if (index == 1) {
	    // Read agent name
	    list.add(st.sval);
	    hashtable.put(key, list);
	  }
	  index++;
	  break;
	case StreamTokenizer.TT_NUMBER:
	  if (debug) {
	    _log.debug("Nb=" + st.nval);
	  }
	  break;
	}
      }
    }
    catch (IOException e) {
      e.printStackTrace();
      return;
    }
  }

  public void printConfiguration()
  {
    Enumeration e = communities.keys();
    while (e.hasMoreElements()) {
      String c = (String) e.nextElement();
      ArrayList l = (ArrayList) communities.get(c);
      _log.debug(c);
      ListIterator it = l.listIterator();
      while (it.hasNext()) {
	_log.debug("\t" + it.next());
      }
    }
  }

  /** Generate one policy file for each community */
  public void generatePolicyFiles()
  {
    Enumeration e = communities.keys();
    while (e.hasMoreElements()) {
      // Retrieve the name of the community
      String aCommunity = (String) e.nextElement();
      // Retrieve the list of all the agents in that community
      ArrayList agentList = (ArrayList) communities.get(aCommunity);

      // Generate the XML document
      if (debug) {
	_log.debug("Generating policy for community " + aCommunity);
      }

      Document document = readPolicyTemplate();

      Enumeration pol = policies.keys();
      while (pol.hasMoreElements()) {
	String key = (String) pol.nextElement();
	ArrayList list = (ArrayList) policies.get(key);
	// The list should contain only one element.
	String value = (String) list.get(0);
	if (debug) {
	  _log.debug("Modifying policy for key=" + key + " - value=" + value);
	}
	insertPolicyElements(document, aCommunity, agentList, key, value);
      }

      savePolicy(document, aCommunity);
    }
  }

  public void insertPolicyElements(Document document,
				   String community,
				   ArrayList agentList,
				   String policyElementName,
				   String policyValue)
  {
    Element rootElement = document.getDocumentElement();
    String rootElementName = rootElement.getNodeName();

    // <Policies> node
    if (!rootElementName.equals("Policies")) {
      throw new IllegalArgumentException("Expecting <Policies>, not "+ rootElementName);
    }

    // <Policy> nodes
    NodeList rootNodeList = rootElement.getChildNodes();
    int nRootNodes = rootNodeList.getLength();

    for (int i = 0 ; i < nRootNodes ; i++) {
      Node subNode = (Node) rootNodeList.item(i);
      if (subNode.getNodeType() != Node.ELEMENT_NODE) {
        continue;
      }
      String subNoodeName = subNode.getNodeName().trim();
      if (!subNoodeName.equals("Policy")) {
	throw new IllegalArgumentException("Expecting <Policy>, not "+ subNoodeName);
      }

      // Assign a name for the policy
      Element policyEl = (Element) subNode;
      policyEl.setAttribute("name", "Policy-" + community);

      // <RuleParam> nodes
      NodeList subNodeList = subNode.getChildNodes();
      int nSubNode = subNodeList.getLength();
      
      for (int j = 0 ; j < nSubNode ; j++) {
	Node rule = (Node) subNodeList.item(j);
	if (!(rule instanceof Element)) {
	  continue;
	}

	Element policyElement = (Element) rule;
	String ruleParamName = policyElement.getNodeName().trim();
	if (ruleParamName.equals("RuleParam")) {
	  String policyPredicate = policyElement.getAttribute("name");
	  if (policyPredicate.equals(policyElementName)) {
	    // This is where we insert specific policies
	    if (debug) {
	      _log.debug("Inserting specific policy for " + policyPredicate);
	    }

	    // <Keyset> nodes
	    NodeList keysetList = rule.getChildNodes();
	    int nKeysetList = keysetList.getLength();
	    for (int k = 0 ; k < nKeysetList ; k++) {
	      Node keyset = keysetList.item(k);
	      if (!(keyset instanceof Element)) {
		continue;
	      }
	      String defaultPolicy = ((Element)keyset).getAttribute("value");
	      if (debug) {
		_log.debug("Default Policy:" + defaultPolicy);
	      }
	      // Insert specific policies
	      ListIterator it = agentList.listIterator();
	      while (it.hasNext()) {
		String agentName = (String) it.next();
		String keyValue = "KeyValue";
		String attr1 = "key";
		String attr2 = "value";

		Element e = document.createElement(keyValue);
		e.setAttribute(attr1, agentName);
		e.setAttribute(attr2, policyValue);

		// Insert element in document
		keyset.insertBefore(e, null);
	      }
	    }
	  }
	}
      }

    }
  }

  private void savePolicy(Document document, String community)
  {
    OutputFormat of = new OutputFormat("xml", "UTF-8", true);
    XMLSerializer serializer = new XMLSerializer(of);

    String outputFileName = outputfileprefix + community + ".xml";

    // Open output policy file
    FileOutputStream out = null;
    try {
      out = new FileOutputStream(outputFileName);
    }
    catch (Exception e) {
      e.printStackTrace();
      return;
    }

    serializer.setOutputByteStream(out);

    try {
      serializer.serialize(document);
      out.close();
    }
    catch (Exception e) {
    }
  }

  private Document readPolicyTemplate()
  {
    DOMParser parser = new DOMParser();
    Document document = null;

    // Open policy template
    FileInputStream in = null;
    try {
      in = new FileInputStream(templateFile);
    }
    catch (Exception e) {
      if (debug) {
	_log.debug("Unable to open policy template file: " + e);
      }
      return null;
    }

    // Parse policy template
    try {
      InputSource inSource = new InputSource(in);
      parser.parse(inSource);
      in.close();
      document = parser.getDocument();
    } catch (Exception e) {
      if (debug) {
	_log.debug("Unable to parse policy template file:" + e);
      }
    }

    return document;

  }

  public static void main(String[] args) {
    String communityConfFile = args[0];
    String policiesFile = args[1];
    String policyTemplate = args[2];
    String outputFilePrefix = args[3];

    _log.debug("===================================================");
    _log.debug("Creating policies for:");
    _log.debug("Policy template file:        " + policyTemplate);
    _log.debug("Community configuration file:" + communityConfFile);
    _log.debug("Policy file:                 " + policiesFile);
    _log.debug("Outputfile prefix:           " + outputFilePrefix);

    PolicyGenerator pg = new PolicyGenerator();
    pg.setCommunityConfigurationFileName(communityConfFile);
    pg.setPolicyFileName(policiesFile);

    pg.setOutputFilePrefix(outputFilePrefix);
    pg.setPolicyTemplate(policyTemplate);

    pg.parseCommunityFile();
    pg.parsePolicyFile();

    pg.generatePolicyFiles();
  }
}
