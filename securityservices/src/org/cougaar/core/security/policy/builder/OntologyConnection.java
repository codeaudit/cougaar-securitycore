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


/*
 * This class and its subclasses have an awkward problem.  It is
 * attempting to bridge a gap between the OntologyRepository
 * interfaces and the TunnelClient/KAoSDirectoryService interface.  I
 * use the OntologyRepository class for the standalone applications
 * and the TunnelClient class for the applications involving remote
 * access to the directory service.
 * 
 * Really this class should have the KAoSDirectoryService interfaces.
 * However it is not clear how to start the KAoSDirectoryService in a
 * standalone application.  The KAoSDirectoryService is abstract
 * (easily fixed) but it also obtains services using a service root.
 * I looked briefly at DAMLBasedKAoSDirectory but this class uses a
 * backwards pointer to the KAoSDirectoryService which is passed to it
 * in its constructor.  This may be fixable?
 *
 * Conceivably if this gets me into trouble we could switch to a mode
 * where all policy building is done locally and I use the tunnel
 * client to commit them???
 *
 */

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

  /*
   * Abstract methods
   */

  public abstract Set getInstancesOf (String conceptName) 
    throws Exception;

  public abstract Vector getPropertiesApplicableTo (String className)
    throws ReasoningException ;

  public abstract String getRangeOnPropertyForClass(String className, 
                                                    String propertyName) 
    throws ReasoningException;

  public abstract Set getSubClassesOf (String className)
    throws Exception;

  public abstract boolean testTrue (String statement) 
    throws ReasoningException;

  /*
   * Not implemented on the tunnelled ontology
   */

  public abstract void loadOntology (DAMLModel myDAMLModel, 
                                     boolean recursiveLoad)
    throws ReasoningException, IOException;


  
  /*
   * Abstract methods requiring a domain manager.
   */
  public abstract Vector getPolicies() throws IOException;

  public abstract void updatePolicies (List addedPolicies,
                                       List changedPolicies,
                                       List removedPolicies) 
    throws IOException;

  public abstract void setConditionalPolicies(Vector condPols)
    throws Exception;
}
