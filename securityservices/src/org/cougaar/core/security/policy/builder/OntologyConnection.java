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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import javax.agent.service.directory.DirectoryFailure;

import jtp.ReasoningException;
import kaos.ontology.management.UnknownConceptException;
import kaos.ontology.util.SerializableOntModelImpl;
import kaos.ontology.vocabulary.RDFConcepts;
import kaos.ontology.vocabulary.RDFSConcepts;
import kaos.policy.information.OntologyInterfaces;
import kaos.policy.information.PolicyInformationManager;


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
 *
 * Conceivably if this gets me into trouble we could switch to a mode
 * where all policy building is done locally and I use the tunnel
 * client to commit them???
 *
 */

public abstract class OntologyConnection
  implements OntologyInterfaces
{
  public static boolean _disableChecking = false;
  /*
   * For various reasons, this class needs intelligence.  I also
   * provide a convenience method for outsiders to load intelligence.
   */

  public OntologyConnection()
  {
    PolicyInformationManager.setOntologyConnection(this);
    PolicyUtils.setOntologyConnection(this);
  }


  public static void disableChecking()
  {
    _disableChecking =  true;
  }

  public void verifySubClass(String smallSet, 
                             String bigSet)
    throws PolicyCompilerException
  {
    if (_disableChecking) {
      return;
    }
    String error = smallSet + " is not a subclass of " + bigSet;
    try {
      if (!testTrue
          ("(" + RDFSConcepts._subClassOf_ + " "
           + smallSet + " " + bigSet + ")")) {
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
    if (_disableChecking) {
      return;
    }
    String error = element + " is not a member of " + container;
    try {
      if (!testTrue
          ("(" + RDFConcepts._type_ + " " + 
           element + " " + container + ")")) {
        throw new PolicyCompilerException(error);
      }
    } catch (ReasoningException re) {
      PolicyCompilerException pe = new PolicyCompilerException(error);
      pe.initCause(re);
      throw pe;
    }
  }

  public void loadDeclarations(Map declarations)
    throws ReasoningException
  {
    for (Iterator instanceIt = declarations.keySet().iterator(); 
         instanceIt.hasNext();) {
      String instanceName = (String) instanceIt.next();
      String className    = (String) declarations.get(instanceName);
      declareInstance(instanceName, className);
    }
  }

  /*
   * Abstract methods
   */

  public abstract Set getInstancesOf (String conceptName) 
    throws UnknownConceptException, DirectoryFailure;

  public abstract Vector getPropertiesApplicableTo (String className)
    throws ReasoningException ;

  public abstract String getRangeOnPropertyForClass(String className, 
                                                    String propertyName) 
    throws ReasoningException;

  public abstract Set getIndividualTargets (String baseTargetClass) 
    throws ReasoningException;

  public abstract void declareInstance(String instanceName,
                                       String className)
    throws ReasoningException;


  public abstract Set getSubClassesOf (String className)
    throws UnknownConceptException, DirectoryFailure;

  public abstract boolean testTrue (String statement) 
    throws ReasoningException;

  /*
   * Not implemented on the tunnelled ontology
   */

  public abstract void loadOntology(SerializableOntModelImpl  myOntModel, 
                                    boolean                    recursiveLoad)
    throws ReasoningException, IOException;


  
  /*
   * Abstract methods requiring a domain manager.
   */
  public abstract List getPolicies() throws IOException;

  public abstract void updatePolicies (List addedPolicies,
                                       List changedPolicies,
                                       List removedPolicies) 
    throws IOException;

  public abstract void setConditionalPolicies(Vector condPols)
    throws Exception;

    /**
     * Get set of namspaces imported by the given namespace. Curently it tries to match the concept name with the local name of the ontology definitions url
     *
     * @param conceptName     The name of the namespace in the Jena format
     *
     * @return                Set of ontology definition url potentially matching the search concept
     */
    public Set getOntologyDefinitionForConcept (String conceptName) 
      throws DirectoryFailure
  {
    throw new DirectoryFailure("Not implemented yet");
  }
}
