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

import com.hp.hpl.jena.daml.DAMLModel;

import java.io.*;
import java.util.*;

import jtp.ReasoningException;

import kaos.ontology.DefaultOntologies;
import kaos.ontology.repository.KAoSContext;
import kaos.ontology.repository.OntologyRepository;
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.ontology.util.JTPStringFormatUtils;
import kaos.ontology.util.ValueNotSet;


public abstract class OntologyConnection
{
  /*
   * For various reasons, this class needs intelligence.  I also
   * provide a convenience method for outsiders to load intelligence.
   */

  public OntologyConnection()
  {
    LocalPolicyInformationManager.giveIntelligence(this);
    PolicyUtils.setOntologyConnection(this);
  }

  public abstract Set getInstancesOf (String conceptName) 
    throws Exception;

  public abstract Vector getPropertiesApplicableTo (String className)
    throws ReasoningException ;

  public abstract String getRangeOnPropertyForClass(String className, 
                                                    String propertyName) 
    throws ReasoningException;

  public abstract Set getSubClassesOf (String className)
    throws Exception;

  public abstract void loadOntology (DAMLModel myDAMLModel, 
                                     boolean recursiveLoad)
    throws ReasoningException, IOException;

  public abstract boolean testTrue (String statement) 
    throws ReasoningException;

  public abstract Vector getPolicies() throws IOException;

  public abstract void updatePolicies (List addedPolicies,
                                       List changedPolicies,
                                       List removedPolicies) 
    throws IOException;

  public void verifySubClass(String smallSet, 
                             String bigSet)
    throws PolicyCompilerException
  {
    String error = smallSet + " is not a subclass of " + bigSet;
    try {
      if (!testTrue
          ("(" + kaos.ontology.RDFSConcepts._subClassOf_ + " " + 
           JTPStringFormatUtils.convertStringToJTPFormat(smallSet) + " " + 
           JTPStringFormatUtils.convertStringToJTPFormat(bigSet) + ")")) {
        throw new PolicyCompilerException(error);
      }
    } catch (ReasoningException re) {
      PolicyCompilerException pe = new PolicyCompilerException(error);
      pe.initCause(re);
      throw pe;
    }
  }

  public void verifyInstanceOf(String element, 
                               String container)
    throws PolicyCompilerException
  {
    String error = element + " is not a member of " + container;
    try {
      if (!testTrue
          ("(" + kaos.ontology.RDFConcepts._type_ + " " + 
           JTPStringFormatUtils.convertStringToJTPFormat(element) + " " + 
           JTPStringFormatUtils.convertStringToJTPFormat(container) + ")")) {
        throw new PolicyCompilerException(error);
      }
    } catch (ReasoningException re) {
      PolicyCompilerException pe = new PolicyCompilerException(error);
      pe.initCause(re);
      throw pe;
    }
  }
}
