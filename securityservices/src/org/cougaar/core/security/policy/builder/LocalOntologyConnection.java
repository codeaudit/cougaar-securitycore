/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */

package org.cougaar.core.security.policy.builder;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import javax.agent.service.directory.DirectoryFailure;

import jtp.ReasoningException;

import kaos.ontology.DefaultOntologies;
import kaos.ontology.management.UnknownConceptException;
import kaos.ontology.repository.OntologyRepository;
import kaos.ontology.vocabulary.RDFConcepts;
import kaos.ontology.util.SerializableOntModelImpl;

public class LocalOntologyConnection extends OntologyConnection
{
  /*
   * For various reasons, this class needs intelligence.  I also
   * provide a convenience method for outsiders to load intelligence.
   */

  private static OntologyRepository  _brains = null;

  public LocalOntologyConnection(Map declarations,
                                 Map agentGroupMap)
  {
    super();
    if (_brains  == null) {
      _brains = new OntologyRepository();
      try {
        _brains.loadOntology("http://ontology.ihmc.us/Policy.owl", true);
        _brains.loadOntology
          ("http://ontology.ihmc.us/Ultralog/UltralogOntologies.owl",
           true);
        PolicyUtils.autoGenerateGroups(declarations, agentGroupMap);
      } catch (Exception e) {
        // If you need to be smart but have no brains you are screwed.
        e.printStackTrace();
        System.exit(-1);
      }
    }
  }

  public Set getInstancesOf (String conceptName) 
    throws UnknownConceptException, DirectoryFailure
  {
    return _brains.getInstancesOf(conceptName);
  }


  /*
   * Implementation of abstract methods from OntologyConnection
   */

  public Vector getPropertiesApplicableTo (String className)
    throws ReasoningException 
  {
    return _brains.getPropertiesApplicableTo(className);
  }

  public String getRangeOnPropertyForClass(String className, 
                                                    String propertyName) 
    throws ReasoningException
  {
    return _brains.getRangeOnPropertyForClass(className,propertyName);
  }

  public Set getIndividualTargets (String baseTargetClass) 
    throws ReasoningException
  {
    return _brains.getResourcesWithValueForProperty(
                                       RDFConcepts._type_, 
                                       baseTargetClass); 
  }


  public void declareInstance(String instanceName,
                               String className)
    throws ReasoningException
  {
    _brains.tellKifString('(' + RDFConcepts._type_ 
                          + ' ' + instanceName 
                          + ' ' + className + ')');
  }


  public Set getResourcesWithValueForProperty (String property, String value)
    throws ReasoningException
  {
    return _brains.getResourcesWithValueForProperty(property,value);
  }



  public Set getSubClassesOf (String className) 
    throws UnknownConceptException, DirectoryFailure
  {
    return _brains.getSubClassesOf(className);
  }


  public boolean testTrue (String statement) 
    throws ReasoningException
  {
    return _brains.testTrue(statement);
  }


  /*
   * Not implemented on the tunnelled ontology
   */

  public void loadOntology (SerializableOntModelImpl  myOntModel, 
                            boolean                   recursiveLoad)
    throws ReasoningException, IOException
  {
    _brains.loadOntology(myOntModel, recursiveLoad);
  }

  /*
   * the following interfaces cannot be implemented without a domain manager.
   */

  public List getPolicies() 
    throws IOException
  {
    throw new IOException("Remote Ultralog Policies Unavailable");
  }

  public void updatePolicies (List addedPolicies,
                              List changedPolicies,
                              List removedPolicies)
    throws IOException
  {
    throw 
      new IOException("Unable to update Policies on remote domain manager");
  }

  public void setConditionalPolicies(Vector condPols)
    throws Exception
  {
    throw new RuntimeException("Unable to update policies on " + 
                               "remote domain manager");
  }

}
