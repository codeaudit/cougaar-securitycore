/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.policy.builder;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.agent.service.directory.DirectoryFailure;

import jtp.ReasoningException;
import kaos.core.service.directory.KAoSDirectoryService;
import kaos.ontology.management.UnknownConceptException;
import kaos.ontology.util.SerializableOntModelImpl;

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
    throws UnknownConceptException, DirectoryFailure
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
    throws UnknownConceptException, DirectoryFailure
  {
    return _kds.getSubClassesOf(className);
  }

  public  boolean testTrue (String statement) 
    throws ReasoningException
  {
    return _kds.testTrue(statement);
  }

  public  void loadOntology(SerializableOntModelImpl   myOntModel, 
                            boolean                    recursiveLoad)
    throws ReasoningException, IOException
  {
    _kds.loadOntology(myOntModel, recursiveLoad);
  }

  public Set getSuperPropertiesOf (String propertyName)
    throws UnknownConceptException  
  {
    return _kds.getSuperPropertiesOf(propertyName);
  }


  public Set getSubPropertiesOf (String propertyName) 
    throws UnknownConceptException, DirectoryFailure
  {
    return _kds.getSubPropertiesOf(propertyName);
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
