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

import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.userauth.UserAuthenticatorImpl;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import jtp.ReasoningException;

import kaos.core.service.directory.KAoSDirectoryService;
import kaos.ontology.management.UnknownConceptException;
import kaos.ontology.util.SerializableDAMLModelImpl;

import com.hp.hpl.jena.daml.DAMLModel;

/**
 * This class represents a connection to the reasoner (the ontology
 * repository) when this code is running in the same java virtual
 * machine as the domain manager.
 */

public class KAoSOntologyConnection extends OntologyConnection
{
  KAoSDirectoryService _kds;

  public KAoSOntologyConnection(KAoSDirectoryService kds)
  {
    super();
    _kds = kds;
  }


  /*
   * Implementation of abstract methods from OntologyConnection
   */

  public  Set getInstancesOf (String conceptName) 
    throws Exception
  {
    return _kds.getInstancesOf(conceptName);
  }

  public  Vector getPropertiesApplicableTo (String className)
    throws ReasoningException
  {
    try {
      return _kds.getPropertiesApplicableTo(className);
    } catch (UnknownConceptException uce) {
      ReasoningException re = new ReasoningException(uce.toString());
      re.initCause(uce);
      throw re;
    }
  }

  public String getRangeOnPropertyForClass(String className, 
                                           String propertyName) 
    throws ReasoningException
  {
    try {
      return _kds.getRangeOnPropertyForClass(className, propertyName);
    } catch (UnknownConceptException uce) {
      ReasoningException re = new ReasoningException(uce.toString());
      re.initCause(uce);
      throw re;
    }
  }

  public Set getIndividualTargets (String baseTargetClass) 
    throws ReasoningException
  {
    try {
      return _kds.getIndividualTargets(baseTargetClass);
    } catch (UnknownConceptException uce) {
      ReasoningException re = new ReasoningException(uce.toString());
      re.initCause(uce);
      throw re;
    }
  }


  public void declareInstance(String instanceName,
                              String className)
    throws ReasoningException
  {
    _kds.declareInstance(instanceName, className);
  }


  public Set getSubClassesOf (String className)
    throws Exception
  {
    return _kds.getSubClassesOf(className);
  }

  public  boolean testTrue (String statement) 
    throws ReasoningException
  {
    return _kds.testTrue(statement);
  }

  public  void loadOntology(SerializableDAMLModelImpl  myDAMLModel, 
                            boolean                    recursiveLoad)
    throws ReasoningException, IOException
  {
    _kds.loadOntology(myDAMLModel, recursiveLoad);
  }


  
  /*
   *  Methods requiring a domain manager.
   */
  public List getPolicies() throws IOException
  {
    return _kds.getPolicies();
  }

  public void updatePolicies (List addedPolicies,
                              List changedPolicies,
                              List removedPolicies) 
    throws IOException
  {
    try {
      _kds.updatePolicies(addedPolicies, changedPolicies, removedPolicies);
    } catch (Exception e) {
      IOException ioe = new IOException();
      ioe.initCause(e);
      throw ioe;
    }
  }

  public  void setConditionalPolicies(Vector condPols)
    throws Exception
  {
    throw new UnsupportedOperationException();
  }

}
