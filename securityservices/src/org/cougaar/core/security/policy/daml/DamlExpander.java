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
import com.hp.hpl.mesa.rdf.jena.model.Model;
import com.hp.hpl.jena.daml.DAMLModel;
import com.hp.hpl.jena.daml.common.DAMLModelImpl;
import kaos.ontology.util.DAMLModelUtils;

/**
 * Expands a DAML policy into XML that can be directly enforced. Currently
 * this expansion is fake, using a matching technique of the DAML to
 * guaranteed input and looking it up in a table and giving the XML output
 * in response.
 */
public class DamlExpander  extends SimplePlugin {

  private SecurityPropertiesService _secprop = null;
  private LoggingService            _log;
  private List                      _damlMap = new ArrayList();
  private IncrementalSubscription   _upu;
  private String                    _expanderFile = "expander.txt";

  private UnaryPredicate _unexPolicyUpdatePredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        return (o instanceof UnexpandedPolicyUpdate);
      }
    };

  /**
   * Sets the input parameter. The parameter is a filename containing
   * DAML filename/XML filename pairs. The DAML file name is loaded
   * and matched against new DAML policy on the blackboard
   * and the corresponding XML policy is then published.
   * 
   * @param o A <code>List</code> of paramters - only one is allowed.
   */
  public void setParameter(Object params) {
    List l = (List) params;
    if (l.size() != 1) {
      throw new IllegalArgumentException("You must have one and only one parameter to DamlExpander");
    } // end of if (l.size() != 1)
    _expanderFile = (String) l.get(0);
  }

  /**
   * Loads the expander table from the file. The file name must contain
   * lines that have 2 or more quoted strings in it separated by whitespace.
   * The first quoted string contains the file name of the DAML triples to
   * match against the input DAML policy. The second and further string is
   * the file name of XML data to publish to the blackboard when the DAML
   * matches. 
   */
  private void loadExpanderFile(String fileName) {
    try {
       
    ConfigFinder cf = ConfigFinder.getInstance();
    File f = cf.locateFile(fileName);
    BufferedReader fileIn = new BufferedReader(new FileReader(f));
    String line;
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    while ((line = fileIn.readLine()) != null) {
      line = line.trim();
      if (line.startsWith("#") || line.length() == 0) {
        continue; // a comment on this line
      } // end of if (line.startsWith("#") || line.length() == 0)
      
      StringTokenizer tok = new StringTokenizer(line,"\"");
      String triple = tok.nextToken();
      File tripleFile = cf.locateFile(triple);
      if (tripleFile == null) {
        if (_log.isWarnEnabled()) {
          _log.warn("Could not find triple file " + triple + " in config path.");
        } // end of if (_log.isWarnEnabled())
        continue;
      } // end of if (tripleFile == null)
      
      DAMLModel policyIn = new DAMLModelImpl();
      policyIn.read(tripleFile.toURL().toString(), "N-TRIPLE");
      Model model = Forgetful.copy(policyIn);

      ArrayList xmlDocs = new ArrayList();
      while (tok.hasMoreTokens()) {
        tok.nextToken(); // between the two strings
        if (!tok.hasMoreTokens()) {
          break; // there's nothing left
        } // end of if (!tok.hasMoreTokens())
        String xml = tok.nextToken();
        File xmlFile = cf.locateFile(xml);
        // pretend for now that I only need a string
        FileReader fxml = new FileReader(xmlFile);
        char buf[] = new char[5000];
        StringBuffer sbuf = new StringBuffer();
        int len;
        while ((len = fxml.read(buf)) != -1) {
          sbuf.append(buf,0,len);
        } // end of while ((len = fxml.read(buf)) > 0)
        InputSource fromString = 
          new InputSource(new StringReader(sbuf.toString()));
        xmlDocs.add(db.parse(fromString));
      } // end of while (tok.hasMoreTokens())
      _damlMap.add(new NVPair(model, (Document[])
                              xmlDocs.toArray(new Document[xmlDocs.size()])));
    } // end of while ((line = fileIn.readLine()) != null)
    } catch (Exception e) {
      _log.error("Couldn't load the expander file", e);
    } // end of try-catch
  }

  public void setupSubscriptions() {
    _log = (LoggingService)
      getBindingSite().getServiceBroker().getService(this,
						     LoggingService.class, 
                                                     null);
    _secprop = (SecurityPropertiesService)
      getBindingSite().getServiceBroker().getService(this, SecurityPropertiesService.class, null);

    _upu = (IncrementalSubscription) subscribe (_unexPolicyUpdatePredicate);
    loadExpanderFile(_expanderFile);
  }
    
  public void execute() {
    _log.debug("PolicyExpanderPlugIn::execute()");

    // check for added UnexpandedPolicyUpdates
    Enumeration upuEnum = _upu.getAddedList();
    List expandedPolicies = new ArrayList();
    while (upuEnum.hasMoreElements()) {
      UnexpandedPolicyUpdate upu = (UnexpandedPolicyUpdate) upuEnum.nextElement();
      List policies = upu.getPolicies();
      Iterator policyIt = policies.iterator();
      while (policyIt.hasNext()) {
        PolicyMsg policyMsg = (PolicyMsg) policyIt.next();

        try {
          PolicyMsg[] newMessages = expandPolicy (policyMsg);
          if (newMessages != null) {
            // replace the newMessage
            for (int i = 0; i < newMessages.length; i++) {
              _log.debug("writing out xml policy: " + newMessages[i]);
              expandedPolicies.add(newMessages[i]);
            } // end of for (int i = 0; i < newMessages.length; i++)
          } // end of if (newMessages != null)
        } catch (Exception xcp) {
          _log.error("Error expanding policy:\n" + policyMsg,
                     xcp);
        }
      }
      publishRemove (upu);
      publishAdd (new ExpandedPolicyUpdate(upu.getUpdateType(),
                                           upu.getLocators(),
                                           expandedPolicies));
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

    // find the XMLContent attribute or DAMLContent
    // (assumption: there is only one XMLContent or DAMLContent attribute)
    Document xmlContent = null;
    Model    damlContent = null;
    for (int i=0; i < attributes.size() && 
           (xmlContent == null || damlContent == null) ; i++) {
      AttributeMsg attrMsg = (AttributeMsg) attributes.elementAt(i);
      if (attrMsg.getName().equals(AttributeMsg.XML_CONTENT)) {
        xmlContent = (Document) attrMsg.getValue();
        break;
      } else if (attrMsg.getName().equals(AttributeMsg.DAML_CONTENT)) {
        String damlString = (String) attrMsg.getValue();
        try {
          damlContent = DAMLModelUtils.constructDAMLModel(damlString);
          damlContent = Forgetful.copy(damlContent);
        } catch (Exception e) {
          _log.warn("Can't expand the DAML Policy", e);
        } // end of try-catch
        break;
      }
    }

    if (damlContent != null && xmlContent == null) {
      if (_log.isDebugEnabled()) {
        _log.debug("DAML recieved: " + getDamlString(damlContent));
      } // end of if (_log.isDebugEnabled())
      // expand the DAML into XML
      Iterator iter = _damlMap.iterator();
      while (iter.hasNext()) {
        NVPair nvp = (NVPair) iter.next();
        if (_log.isDebugEnabled()) {
          _log.debug("Comparing against: " + getDamlString(nvp.daml));
        } // end of if (_log.isDebugEnabled())
              
        if (nvp.daml.equals(damlContent)) {
          // found a match for the daml content
          PolicyMsg pm[] = new PolicyMsg[nvp.xmls.length];
          for (int i = 0; i < nvp.xmls.length; i++) {
            Element l = nvp.xmls[i].getDocumentElement();
            String type = l.getAttribute("type");
            String name = l.getAttribute("name");
            pm[i] = new PolicyMsg(UniqueIdentifier.GenerateUID(),
                                  name,
                                  policyMsg.getDescription(),
                                  type,
                                  policyMsg.getAdministrator(),
                                  policyMsg.getSubjects(),
                                  policyMsg.isInForce());
            AttributeMsg msg = 
              new AttributeMsg(AttributeMsg.XML_CONTENT, nvp.xmls[i], true);
            pm[i].setAttribute(msg);
          } // end of for (int i = 0; i < nvp.xmls.length; i++)
          return pm;
        }
      } // end of while (iter.hasNext())
      _log.warn("Could not find match for DAML policy");
    }
    return null;
  }
  
  private static String getDamlString(Model model) {
    try {
      StringWriter strw = new StringWriter();
      PrintWriter  pw   = new PrintWriter(strw);
      model.write(pw);
      pw.close();
      return strw.toString();
    } catch (Exception e) {
      return "Couldn't get daml string: " + e.toString();
    } // end of try-catch
  }

  private static class NVPair {
    public Model daml;
    public Document xmls[];

    public NVPair() {}
    public NVPair(Model daml, Document xmls[]) {
      this.daml  = daml;
      this.xmls  = xmls;
    }
  }
}

