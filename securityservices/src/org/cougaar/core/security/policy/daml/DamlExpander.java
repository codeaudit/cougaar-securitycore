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
  private String                    _expanderFile = "expansion.list";
  private int                       _expansionNum = 1;
  private boolean                   _lastExpansion = true;

  private static final UnaryPredicate FIRST_EXPANSION = new UnaryPredicate() {
      public boolean execute(Object o) {
        return (o instanceof UnexpandedPolicyUpdate &&
                !(o instanceof DamlPolicyExpansion));
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
	      debuglog("Found daml policy"); 
	      debuglogModel(policy);
	      expansion.add(Forgetful.copy(policy));
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
    
  public void execute() {
    if (_expanderFile != null) {
      debuglog("(Re)loading Expander initialization file");
      loadExpanderFile(_expanderFile);
      debuglog("Finished loading Expander initialization file");
    } // end of if (_expanderFile != null)
    debuglog("DamlExpander::execute()");

    //    checkRemovedList();
    // check for added UnexpandedPolicyUpdates
    Enumeration upuEnum = _upu.getAddedList();
    List expandedPolicies = new ArrayList();
    while (upuEnum.hasMoreElements()) {
      debuglog("In upu Enum loop");

      UnexpandedPolicyUpdate upu = (UnexpandedPolicyUpdate) upuEnum.nextElement();
      List policies = upu.getPolicies();
      Iterator policyIt = policies.iterator();

      while (policyIt.hasNext()) {
	debuglog("In Policy Iterator loop");

        PolicyMsg policyMsg = (PolicyMsg) policyIt.next();
	if (policyMsg.isInForce()) {
	    debuglog("Policy is in Force");
	} else {
	    debuglog("Policy should not be in Force");
	}

	try {
	    PolicyMsg[] newMessages = expandPolicy(policyMsg);
	    if (newMessages != null) {
		// replace the newMessage
		for (int i = 0; i < newMessages.length; i++) {
		    debuglog("writing out policy: " + newMessages[i]);
		    expandedPolicies.add(newMessages[i]);
		} // end of for (int i = 0; i < newMessages.length; i++)
	    }  // end of if (newMessages != null)
	} catch (Exception xcp) {
	    _log.error("Expansion #" + _expansionNum + 
		       ": Error expanding policy:\n" + policyMsg,
		       xcp);
	}
      }
      publishRemove(upu);
      
      Object newPolicy;
      if (_lastExpansion) {
        newPolicy = new ExpandedPolicyUpdate(upu.getUpdateType(),
                                             upu.getLocators(),
                                             expandedPolicies);
      } else {
        newPolicy = new DamlPolicyExpansion(upu.getUpdateType(),
                                            upu.getLocators(),
                                            expandedPolicies,
                                            _expansionNum + 1);
      } 
      
      publishAdd(newPolicy);
    }
  }

  /**
   * This function expands a policy.
   *
   * The original policy should be kept intact, in that no existing fields
   * are removed or changed. You should expand the policy by
   * adding to the original. You may add new attributes, or add new key-value
   * pairs, or add sub-messages to the original policy, whichever way you
   * prefer, as long as the enforcers can parse the additions. The current
   * KAoS infrastructure does not parse these additions so no restrictions
   * are placed on the types of things you add to the original policy.
   *
   * @param policy	Policy message to expand
   */
  private PolicyMsg[] expandPolicy (PolicyMsg policyMsg) {
    // get the attributes of the policy
    Vector attributes = policyMsg.getAttributes();
    Model damlContent=getDamlContentFromAttributes(attributes);

    if (damlContent == null) {
      return new PolicyMsg[] { policyMsg }; // no expansion
    } // end of if (damlContent == null)
    
      // expand the DAML 
    Iterator iter = _damlMap.iterator();

    // try to find a matching DAML:
    while (iter.hasNext()) {
      debuglog("Looping through the possible matches");

      Object map[] = (Object []) iter.next();
      Model daml   = (Model) map[0];

      debuglog("Comparing against: ");
      debuglogModel(daml);

      // Why do I need a forgetful copy here ????!
      // It may have something to do with casts from Model to DAMLModel???
      try {
	  if (Forgetful.copy(daml).equals(Forgetful.copy(damlContent))) {
	      debuglog("Got a match.");

	      // found a match for the daml content
	      ArrayList pm = new ArrayList();

	      debuglog("map.length = " + map.length);
	      for (int i = 1; i < map.length; i++) {
		  PolicyMsg newPolicy;
		  if (map[i] instanceof Model) {
		      newPolicy = policyFromModel(policyMsg, (Model) map[i]);
		  } else {
		      // XML content
		      newPolicy = policyFromXML(policyMsg, (Document) map[i]);
		  } 
		  pm.add(newPolicy);
	      }
	      return (PolicyMsg[]) pm.toArray(new PolicyMsg[pm.size()]);
	  }
      } catch (Exception e) {
	  _log.error("Expansion #" + _expansionNum + 
		     ": Exception while comparing policies for a match", e);
      }
    } // end of while (iter.hasNext())
    _log.warn("--------------------------------------------------------");
    _log.warn("Expansion #" + _expansionNum + 
	      ": Could not find match for DAML policy");
    _log.warn("Expansion #" + _expansionNum + 
	      ": DAML Policy in question has the form: ");
    try {
	_log.warn(Forgetful.beautify(damlContent));
	_log.warn("--------------------------------------------------------");
    } catch (Exception e) {
	_log.error("Expansion #" + _expansionNum + 
		   "Exception occured while trying to display unmatched policy", e);
    }

    return new PolicyMsg[] { policyMsg };
  }

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

  private static PolicyMsg policyFromXML(PolicyMsg policyMsg,
                                         Document xmlDoc) {
    Element l = xmlDoc.getDocumentElement();
    String type = l.getAttribute("type");
    String name = l.getAttribute("name");
    
    PolicyMsg pm = new PolicyMsg(UniqueIdentifier.GenerateUID(),
                                 name,
                                 policyMsg.getDescription(),
                                 type,
                                 policyMsg.getAdministrator(),
                                 policyMsg.getSubjects(),
                                 policyMsg.isInForce());
    AttributeMsg msg = 
      new AttributeMsg(AttributeMsg.XML_CONTENT, xmlDoc, true);
    pm.setAttribute(msg);
    return pm;
  }

  private static PolicyMsg policyFromModel(PolicyMsg policyMsg, Model model) {
    PolicyMsg pm = new PolicyMsg(UniqueIdentifier.GenerateUID(),
                                 policyMsg.getName(),
                                 policyMsg.getDescription(),
                                 policyMsg.getType(),
                                 policyMsg.getAdministrator(),
                                 policyMsg.getSubjects(),
                                 policyMsg.isInForce());
    AttributeMsg msg = 
      new AttributeMsg(AttributeMsg.DAML_CONTENT, model, true);
    pm.setAttribute(msg);
    return pm;
  }

  private void checkRemovedList() {
    // check for added UnexpandedPolicyUpdates
    Enumeration upuEnumRemoved = _upu.getRemovedList();
    while (upuEnumRemoved.hasMoreElements()) {
      debuglog("In upu Enum loop");

      UnexpandedPolicyUpdate upu = 
	  (UnexpandedPolicyUpdate) upuEnumRemoved.nextElement();
      List policies = upu.getPolicies();
      Iterator policyIt = policies.iterator();

      while (policyIt.hasNext()) {
	debuglog("In Policy Iterator loop");

        PolicyMsg policyMsg = (PolicyMsg) policyIt.next();
	if (policyMsg.isInForce()) {
	    debuglog("Policy is in Force");
	} else {
	    debuglog("Policy should not be in Force");
	}

	try {
	    PolicyMsg[] newMessages = expandPolicy(policyMsg);
	    if (newMessages != null) {
		// replace the newMessage
		for (int i = 0; i < newMessages.length; i++) {
		    debuglog("xxxx" + newMessages[i]);

		} // end of for (int i = 0; i < newMessages.length; i++)
	    }  // end of if (newMessages != null)
	} catch (Exception xcp) {
	    debuglog("Error looking through removed list");
	}
      }
    }
  }

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
			 ": Readable (Hopefully) Version of Policy: ");
	      _log.debug(Forgetful.beautify(model));
	  } catch (Exception e) {
	      _log.error("Expansion #" + _expansionNum + 
			 ": Couldn't print model", e);
	  }
      } // end of if (_log.isDebugEnabled())      
    }
}

