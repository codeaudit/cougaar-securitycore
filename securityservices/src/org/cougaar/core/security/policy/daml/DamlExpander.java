/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
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


package org.cougaar.core.security.policy.daml;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Vector;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.StringTokenizer;
import java.io.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

// The locator stuff does not compile.  According to the documentation it 
// should be found in javax.agent.Locator.  But our compilation environment 
// can't find this and I also couldn't find documentation for this class.
// I will just use Object and Object.equals
// import javax.agent.Locator;

import kaos.core.util.KAoSConstants;

import org.w3c.dom.Element;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;


// Core Cougaar
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.SimplePlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.util.ConfigFinder;

// KAoS policy management
import kaos.policy.util.PolicyConstants;
import kaos.core.util.*;
import safe.util.*;
import safe.policyManager.PolicyExpanderPlugin;
import kaos.core.util.UniqueIdentifier;

// Cougaar security services
import org.cougaar.core.security.policy.daml.DamlPolicyAtom;
import org.cougaar.core.security.policy.daml.Forgetful;
import org.cougaar.core.security.policy.XMLPolicyCreator;
import org.cougaar.core.security.policy.TypedPolicy;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.util.DOMWriter;
// DAML stuff

import com.hp.hpl.jena.daml.*;
import com.hp.hpl.jena.daml.common.DAMLModelImpl;
import com.hp.hpl.mesa.rdf.jena.mem.ModelMem;
import com.hp.hpl.mesa.rdf.jena.model.*;
import com.hp.hpl.mesa.rdf.jena.vocabulary.*;
import com.hp.hpl.mesa.rdf.jena.model.Model;
import kaos.ontology.util.DAMLModelUtils;

/**
 * Expands a DAML policy into either another DAML policy or XML. Currently
 * this expansion is fake, using a matching technique of the DAML to
 * the new policy.
 */
public class DamlExpander  extends SimplePlugin {

  private SecurityPropertiesService _secprop = null;
  private LoggingService            _log;
  private List                      _damlMap = new ArrayList();
  private IncrementalSubscription   _upu;
  private Vector                    _damlPolicyAtoms = new Vector();
  private String                    _expanderFile = "expansion.list";
  private int                       _expansionNum = 1;
  private boolean                   _lastExpansion = true;

  private static final UnaryPredicate FIRST_EXPANSION = new UnaryPredicate() {
      public boolean execute(Object o) {
        return (o instanceof UnexpandedPolicyUpdate);
      }
    };

  private UnaryPredicate _unexPolicyUpdatePredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof DamlPolicyExpansion) {
          DamlPolicyExpansion dpe = (DamlPolicyExpansion) o;
          return (dpe.getExpansionNum() == _expansionNum);
        }
        return false;
      }
    };


    // -------------------------------------------------------
    // Initialization Routines.
    //    True - loadExpanderFile is called many times but it is still
    //           an initialization file.  By reloading it gives us the
    //           chance to alter the expansion without needing to
    //           restart the node.
    // -------------------------------------------------------

  /**
   * Sets the input parameter. The parameter is a filename containing
   * DAML filename/DAML filename pairs.
   * 
   * @param o A <code>List</code> of paramters - only one is allowed.
   */
  public void setParameter(Object params) {
    List l = (List) params;
    if (l.size() < 1) {
      throw new IllegalArgumentException("You must have one and only one parameter to DamlExpander");
    } // end of if (l.size() != 1)
    _expanderFile = (String) l.get(0);
    if (l.size() >= 2) {
      _expansionNum = Integer.parseInt((String) l.get(1));
    } // end of if (l.size() >= 2)
    if (l.size() > 2) {
      _lastExpansion = Boolean.valueOf((String) l.get(2)).booleanValue();
    } 
    System.out.println("Parameters set" + _expanderFile);
  }

  /**
   * reports errors in the triple-to-expansion file
   */
  private void logFileError(int lineNum, File f, String message) {
    if (message == null) {
      message = "Expecting a pair of quoted triple file names";
    } // end of if (message == null)
    
    _log.warn("Expansion #" + _expansionNum + 
	      ": Error on line: " + lineNum + " of " + f + ": " + message);
  }

  /**
   * Loads the expander table from the file. The file name must contain
   * lines that have 2 or more quoted strings in it separated by whitespace.
   * The first quoted string contains the file name of the DAML triples to
   * match against the input DAML policy. The rest are file names that
   * either contain DAML triples (for DAML-to-DAML expansion) or XML
   * for (DAML-to-XML policy expansion).
   */
  private void loadExpanderFile(String fileName) {
    _damlMap = new ArrayList();
    try {
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      DocumentBuilder db = dbf.newDocumentBuilder();
      ConfigFinder cf = ConfigFinder.getInstance();
      File f = cf.locateFile(fileName);
      BufferedReader fileIn = new BufferedReader(new FileReader(f));
      String line;
      int lineNum = 0;
      while ((line = fileIn.readLine()) != null) {
	debuglog("Reading line from file: " + line);

        // read a line
        lineNum++;
        line = line.trim();
        if (line.startsWith("#") || line.length() == 0) {
          continue; // a comment on this line
        } // end of if (line.startsWith("#") || line.length() == 0)

        Object expansion[] = parseExpansion(line, lineNum, f, db, cf);
        if (expansion != null) {
          _damlMap.add(expansion);
        } // end of if (expansion != null)
      } // end of while ((line = fileIn.readLine()) != null)
    } catch (Exception e) {
      _log.error("Expansion #" + _expansionNum + 
		 ": Couldn't load the expander file", e);
    } // end of try-catch
  }

  /**
   * parses one line of the daml-to-expansion file
   */
  private Object[] parseExpansion(String line, int lineNum, File f,
                                  DocumentBuilder db,
                                  ConfigFinder cf) {
    StringTokenizer tok = new StringTokenizer(line,"\"");

    ArrayList expansion = new ArrayList();
    while (tok.hasMoreTokens()) {
      String fname = tok.nextToken();
      File file = cf.locateFile(fname);

      if (file == null) {
	  logFileError(lineNum, f, "Could not find file " + fname + 
		       " in config path.");
	  return null;
      } // end of if (file == null)

      try {
        // try policy expansion
	  debuglog("Trying policy expansion on " + file.getName());
	  if (file.getName().endsWith(".daml")) {
	      debuglog("Trying daml policy Expansion");
	      // try DAML triples
	      DAMLModel policy = new DAMLModelImpl();
	      policy.read(new FileReader(file), "", "RDF/XML");
	      // debuglog("Found daml policy"); 
	      // debuglogModel(policy);
	      expansion.add(policy);
	  } else {
	      debuglog("Trying xml policy expansion");
	      Document xmlDoc = db.parse(file);
	      Element l = xmlDoc.getDocumentElement();
	      String type = l.getAttribute("type");
	      String name = l.getAttribute("name");
	      if (type == null || name == null) {
		  logFileError(lineNum, f, "XML policy from " + file + 
			       " must have a name and type attribute");
		  return null;
	      } // end of if (type == null || name == null)
	      expansion.add(xmlDoc);
	  } // end of if (file.getName().endsWith(".daml"))
        } catch (Throwable e) {
          logFileError(lineNum, f, "File " + file + 
                       " is not a valid DAML or XML policy");
          return null;
        } // end of try-catch
      if (!tok.hasMoreTokens()) {
        break;
      } // end of if (!tok.hasMoreTokens())
      tok.nextToken(); // space between expansion
    }
    if (expansion.size() != 0) {
      if (expansion.size() == 1) {
        logFileError(lineNum, f, "Only found one quoted file name. Expecting two or more");
      } else if (!(expansion.get(0) instanceof Model)) {
        logFileError(lineNum, f, "The first file name must refer to a DAML triples file");
      } else {
        // all is good
	  debuglog("At end of parseExpansion:");
        return expansion.toArray();
      } 
    } 
    return null;
  }

  public void setupSubscriptions() {
    _log = (LoggingService)
      getBindingSite().getServiceBroker().getService(this,
						     LoggingService.class, 
                                                     null);
    DamlPolicyAtom.setlog(_log);
    _secprop = (SecurityPropertiesService)
      getBindingSite().getServiceBroker().getService(this, SecurityPropertiesService.class, null);

    if (_expansionNum == 1) {
      _upu = (IncrementalSubscription) subscribe (FIRST_EXPANSION);
    } else {
      _upu = (IncrementalSubscription) subscribe (_unexPolicyUpdatePredicate);
    } 

    if (_log.isInfoEnabled()) {
      _log.info("Expansion #" + _expansionNum + 
		": , using file name " +
                _expanderFile + 
                (_lastExpansion 
                 ? ", is last" 
                 : ", will pass on to next expander"));
    } // end of if (_log.isInfoEnabled())

  }

    // -------------------------------------------------------
    // End of Initialization Routines.
    // -------------------------------------------------------

// This routine is called when a set of policy updates occur.  Its
// job is to generate a collection of low level policy updates.  It
// functions by
//   1. looping through all the policy updates
//      2. for each policy update it starts looping through the policy 
//         messages.
//          3. xml policies are separated out to be republished
//             without change 
//          4. daml policies are collected together to be analyzed later.
//  5. Finally at the end the passthrough polcies are send and the
//     work of generating the daml policy update begins.

// The logical path through all this code is
//   UnexpandedPolicyUpdate/DamlPolicyExpansion
//       is converted to PolicyMsg s
//           is converted to DAML policies (or ignored)
//           is processed by policy manipulation
//       is converted back to PolicyMsg s
//   is converted back to DamlPolicyExpansion s which are published


  public void execute() {
    if (_expanderFile != null) {
      debuglog("(Re)loading Expander initialization file");
      loadExpanderFile(_expanderFile);
      debuglog("Finished loading Expander initialization file");
    } // end of if (_expanderFile != null)
    debuglog("DamlExpander::execute()");

    Enumeration upuEnum = _upu.getAddedList();
    List passThroughPolicies = new Vector();
    while (upuEnum.hasMoreElements()) {
      debuglog("In upu Enum loop");

      Object update = upuEnum.nextElement();
      String updateType;
      List policies;
      List locators;
      Vector subjects = new Vector();

      if (update instanceof UnexpandedPolicyUpdate) {
	UnexpandedPolicyUpdate upu = (UnexpandedPolicyUpdate) update;
	policies = upu.getPolicies();
	updateType = upu.getUpdateType();
	locators = upu.getLocators();
      } else {
	DamlPolicyExpansion upu = (DamlPolicyExpansion) update;
	policies = upu.getPolicies();
	updateType = upu.getUpdateType();
	locators = upu.getLocators();
      }
      debuglog("Policy update with updateType = " + updateType + 
	       " and " + locators.size() + " locators.");

      if (policies == null) { 
	  continue;
      }
      Iterator policyIt = policies.iterator();

      while (policyIt.hasNext()) {
	debuglog("In Policy Iterator loop");
	boolean first_policy_iteration = true;

	if (!first_policy_iteration && 
	    (updateType == KAoSConstants.SET_POLICIES 
	     || updateType == KAoSConstants.CHANGE_POLICIES)) {
	  updateType = KAoSConstants.ADD_POLICIES;
	}

        PolicyMsg policyMsg = (PolicyMsg) policyIt.next();
	if (isDAMLpolicyMsg(policyMsg)) {
	    if (!policyMsg.isInForce()) { 
		debuglog("Recieved a policy that is not in force");
		continue; 
	    }
	    debuglog("Starting processing of daml policy message");
	    subjects.addAll(policyMsg.getSubjects());
	    processDAMLPolicyMsg(policyMsg, 
				 updateType,
				 locators);
	} else {
	    debuglog("This policy was not a daml policy");
	    passThroughPolicies.add(policyMsg);
	}
	first_policy_iteration = false;
      }
      publishRemove(update);
      
      publishAdd(new ExpandedPolicyUpdate(updateType,
					  locators,
					  passThroughPolicies));
      sendPolicyUpdateFromDAML(subjects, locators);
    }
  }

    // Is the Policy message an attribute message.

  private boolean isDAMLpolicyMsg(PolicyMsg p) {
      Vector attributes = p.getAttributes();
      for (int i=0; i < attributes.size(); i++) {
	  AttributeMsg attrMsg = (AttributeMsg) attributes.elementAt(i);
	  if (attrMsg.getName().equals(AttributeMsg.DAML_CONTENT)) {
	      return true;
	  }
      }
      return false;
  }

    // This function maintains the set of policies that hold.
  private void processDAMLPolicyMsg(PolicyMsg    policyMsg,
				    String       updateType,
				    List         locators) {
      debuglog("processing daml message");
      debuglog("Before processing " + _damlPolicyAtoms.size() + 
	       " atoms found.");
      debuglog("UpdateType = " + updateType);
      Vector attributes = policyMsg.getAttributes();
      Model damlContent=getDamlContentFromAttributes(attributes);
      //      Iterator iter = locators.iterator();
      //      while (iter.hasNext()) {
      //	  Object locator = iter.next();
	  DamlPolicyAtom a = new DamlPolicyAtom(damlContent
						// , locator
						);
	  debuglog("the new policy is listed? = " + 
		   (_damlPolicyAtoms.contains(a)));
	  if (updateType == KAoSConstants. SET_POLICIES || 
	      updateType == KAoSConstants.CHANGE_POLICIES) {
	      _damlPolicyAtoms = new Vector();
	      _damlPolicyAtoms.add(a);
	  } else if (updateType == KAoSConstants.ADD_POLICIES &&
		     !(_damlPolicyAtoms.contains(a))) {
	      if (!(_damlPolicyAtoms.add(a))) {
		  _log.error("Adding atom failed!!");
	      }
	  } else if (updateType == KAoSConstants.REMOVE_POLICIES) {
	      if (!(_damlPolicyAtoms.remove(a))) {
		  _log.error("Removing atom failed!");
	      }
	  } else {
	      _log.error("Unkown updateType (" + updateType + 
			 ") leading to mismanagement " +
			 "of the daml policy set");
	  }
	  debuglog("After processing " + _damlPolicyAtoms.size() + 
		   " atoms found.");
     //} // Matches while (iter.hasNext()) {
  }

// This routine runs after a collection of policy updats have arrived.
// It calculates a policy update (based on DAML policies) for each
// locator.  It 
//    1. collects all the high level daml policies for the locator, 
//    2. calculates the expansion of the resulting high level daml
//       policy into a set of low level policy messages, and finally
//    3. generates a policy update for the next level down.
  private void sendPolicyUpdateFromDAML(Vector subjects, List locators) {
      try {
	  Vector expandedPolicies = new Vector();
	  //	  Iterator loc_iter = locators.iterator();
	  //	  while (loc_iter.hasNext()) {
	      Model  high_model = new DAMLModelImpl();
	      //  Object locator = loc_iter.next();
	      Iterator policy_iter = _damlPolicyAtoms.iterator();
	      while (policy_iter.hasNext()) {
		  DamlPolicyAtom policyAtom 
		      = (DamlPolicyAtom) policy_iter.next();
		  //  if (policyAtom.locator == locator) {
		      high_model.add(policyAtom.policy);
		      // } // matches if (policyAtom.locator == locator)
	      }
	      debuglog("Combined policy created");
	      Vector expandedPolicyMsgs = getLowPolicyMsgsFromHigh(subjects, 
								   high_model);
	      Object newPolicyUpdate;
	      List locatorList = new  Vector();
	      // locatorList.add(locator);
	      if (_lastExpansion) {
		  newPolicyUpdate = 
		      new ExpandedPolicyUpdate(KAoSConstants.SET_POLICIES,
					       locatorList,
					       expandedPolicyMsgs);
	      } else {
		  newPolicyUpdate = 
		      new DamlPolicyExpansion(KAoSConstants.SET_POLICIES,
					      locatorList,
					      expandedPolicyMsgs,
					      _expansionNum + 1);
	      }
	      publishAdd(newPolicyUpdate);
	      //	  } // matches while (loc_iter.hasNext())
      } catch (Exception e) {
	  _log.error("Could not generate combined policies", e);
      }
  }

    // This function generates the low level policy messages from a
    // high level daml policy.  We go searching through the expansion
    // list for a possible match.  If I find one then I create Policy
    // Messages.  I have to do them slightly differently if they are
    // xml or daml. I collect them up and return them.

  private Vector getLowPolicyMsgsFromHigh(Vector subjects, Model model) {
      Iterator iter = _damlMap.iterator();

      debuglog("The model to match is");
      debuglogModel(model);
      // try to find a matching DAML:
      int counter = 0;
      while (iter.hasNext()) {
	  debuglog("Looping through the possible matches");
	  debuglog("Working on the " + (counter++) + " member of the file");

	  Object map[] = (Object []) iter.next();
	  Model daml   = (Model) map[0];
	    
	  debuglog("Comparing against: ");
	  debuglogModel(daml);

	  try {
	      if ((Forgetful.copy(daml)).equals((Forgetful.copy(model)))) {
		  debuglog("Got a match.");
		    
		  // found a match for the daml content
		  Vector pmVector = new Vector();
		    
		  debuglog("map.length = " + map.length);
		  for (int i = 1; i < map.length; i++) {
		      PolicyMsg newPolicy;
		      if (map[i] instanceof Model) {
			  newPolicy = 
			      policyMsgFromModelPolicy(subjects, 
						       (Model) map[i]);
		      } else {
			  // XML content
			  newPolicy = 
			      policyMsgFromXMLPolicy(subjects, 
						     (Document) map[i]);
		      } 
		      debuglog("Size of attributes in outgoing policy msg" +
			       newPolicy.getAttributes().size());
		      pmVector.add(newPolicy);
		  }
		  return pmVector;
	      }
	  } catch (Exception e) {
	      _log.error("Expansion #" + _expansionNum + 
			 ": Exception while comparing policies for a match", e);
	      return null;
	  }
	  debuglog("No match there");
      } // end of while (iter.hasNext())
      _log.info("---------------------------------------------");
      _log.info("Unmatched daml policy");
      try {
	  _log.info(Forgetful.beautify(model));
      } catch (Exception e) {
	  _log.error("Failed to print daml model");
      }
      _log.info("---------------------------------------------");
      return null;
  }

    // This routine gets the Daml content from the policy message
    // attributes. There are two cases, the daml content is a string
    // or the daml content is a model already.

  private Model getDamlContentFromAttributes(Vector attributes) {
      // find the DAMLContent
      Model    damlContent = null;
      for (int i=0; i < attributes.size() && damlContent == null ; i++) {
	  debuglog("In attributes loop i = " + i);

	  AttributeMsg attrMsg = (AttributeMsg) attributes.elementAt(i);
	  if (attrMsg.getName().equals(AttributeMsg.DAML_CONTENT)) {
	      debuglog("Thinks attribute is DAML Content");

	      Object val = attrMsg.getValue();
	      if (val instanceof Model) {
		  debuglog("Policy from message is already a daml model:");
		  damlContent = (Model) val;	
	      } else if (val instanceof String) {
		  debuglog("It is believed to be a string representing a daml policy");
		  debuglog("Here is the string: " + (String) val);

		  String damlString = (String) val;
		  try {
		      damlContent = new DAMLModelImpl();
		      ((DAMLModel) damlContent).getLoader().setLoadImportedOntologies(false);
		      damlContent.read(new StringReader(damlString),"");
		      debuglog("After reading the model from a string: ");
		      damlContent = Forgetful.copy(damlContent);
		  } catch (Exception e) {
		      _log.warn("Expansion #" + _expansionNum + 
				": Can't expand the DAML Policy", e);
		      return null;
		  } // end of try-catch
	      }
	  }
      }
      if (damlContent != null) {
	  debuglog("here is the policy coming from the attributes");
	  debuglogModel(damlContent);
      }
      return damlContent;
  }

    // These two routines are probably wrong.  It is difficult to know
    // what to do here.  

    // Take a policy  in the form of an xml document and return a
    // policy message.

  private PolicyMsg policyMsgFromXMLPolicy(Vector subjects,
					   Document xmlDoc) {
      Element l = xmlDoc.getDocumentElement();
      String type = l.getAttribute("type");
      String name = l.getAttribute("name");
    
      PolicyMsg pm = new PolicyMsg(UniqueIdentifier.GenerateUID(),
				   name,
				   "Expanded Policy From DAML Policy Expander",
				   type,
				   null,
				   subjects,
				   true);
      debuglog("Making PolicyMsg from xml: "+ xmlDoc.toString());
      AttributeMsg msg = 
	  new AttributeMsg(AttributeMsg.XML_CONTENT, xmlDoc, true);
      pm.setAttribute(msg);
      return pm;
  }

    // Take a policy in the form of a daml policy and return a policy
    // message.
  private PolicyMsg policyMsgFromModelPolicy(Vector subjects,
					     Model model) {
    PolicyMsg pm = new PolicyMsg(UniqueIdentifier.GenerateUID(),
                                 "ExpandedPolicy",
                                 "Policy From DAML Policy Expander",
                                 "DAML",
                                 null,
                                 subjects,
                                 true);
    debuglog("Making PolicyMsg from daml");
    debuglogModel(model);
    AttributeMsg msg = 
      new AttributeMsg(AttributeMsg.DAML_CONTENT, model, true);
    if (! pm.setAttribute(msg)) {
      _log.error("Expansion #" + _expansionNum + 
		 "PolicyMsg.setAttribute failed");
    }
    return pm;
  }
    //---------------------------------------------------------------
    // Silly Utility routines...
    //---------------------------------------------------------------

  private void debuglog(String msg) {
      if (_log.isDebugEnabled()) {
	  _log.debug("Expansion #" + _expansionNum + ": " + msg);
      } // end of if (_log.isDebugEnabled())      
  }

  private void debuglogModel(Model model) {
      if (_log.isDebugEnabled()) {
	  try {
	      StringWriter output = new StringWriter();
	      _log.debug("Expansion #" + _expansionNum + 
			 ": Bad Version: ");
	      model.write((Writer) output, "RDF/XML-ABBREV");
	      _log.debug(output.toString());

	      _log.debug("Expansion #" + _expansionNum + 
			 ": Good Version (Hopefully): ");
	      _log.debug(Forgetful.beautify(model));
	      _log.debug("End of printout of model");
	  } catch (Exception e) {
	      _log.error("Expansion #" + _expansionNum + 
			 ": Couldn't print model", e);
	  }
      } // end of if (_log.isDebugEnabled())      
    }
}

