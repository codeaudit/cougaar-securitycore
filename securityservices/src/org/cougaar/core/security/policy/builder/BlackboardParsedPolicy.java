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

import org.cougaar.core.security.policy.ontology.EntityInstancesConcepts;
import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.security.policy.ontology.UltralogActionConcepts;
import org.cougaar.core.security.policy.ontology.UltralogActorConcepts;
import org.cougaar.core.security.policy.ontology.UltralogEntityConcepts;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import kaos.ontology.util.ClassNameNotSet;
import kaos.ontology.util.RangeIsBasedOnAClass;
import kaos.policy.util.KAoSPolicyBuilderImpl;


public class BlackboardParsedPolicy extends ParsedAuthenticationPolicy
{
  private Set    _accessModes;
  private Set    _objectTypes;
   
  public BlackboardParsedPolicy(String  policyName,
                                String  plugInRole,
                                Set     accessModes,
                                Set     objectTypes)
    throws PolicyCompilerException
  {
    super(policyName, 
          2,
          true,
          ULOntologyNames.pluginsInRoleClassPrefix + plugInRole,
          UltralogActionConcepts.BlackBoardAccess());
    _accessModes = accessModes;
    _objectTypes  = objectTypes;
    makeDescription(plugInRole);
    enforceBlackboardConstraints();
  }

  /**
   * build the description of the policy from the arguments.  For readability,
   * it should probably  be called before enforceBlackboardContraints.
   */
  private void makeDescription(String plugInRole)
  {
    _description = "A plugin in the role " + plugInRole + " can ";
    {
      Iterator accessModesIt = _accessModes.iterator();
      String   accessMode    = (String) accessModesIt.next();
      _description += accessMode;
      while (accessModesIt.hasNext()) {
        accessMode = (String) accessModesIt.next();
        _description += (", " + accessMode);
      }
    }
    _description += " objects of type ";
    {
      Iterator objectTypesIt = _objectTypes.iterator();
      String   objectType    = (String) objectTypesIt.next();
      _description += objectType;
      while (objectTypesIt.hasNext()) {
        objectType = (String) objectTypesIt.next();
        _description += (", " + objectType);
      }
    }
  }


  /**
   * This routine ensures certain consistency requirements involving which 
   * access modes imply which other access modes.
   */
  public void enforceBlackboardConstraints()
    throws PolicyCompilerException
  {
    if (_accessModes.contains("Add")) {
      _accessModes.add("Read");
      _accessModes.add("Write");
      _accessModes.add("Create");
    }
    if (_accessModes.contains("Change")) {
      _accessModes.add("Read");
      _accessModes.add("Write");
    }
    if (_accessModes.contains("Query")) {
      _accessModes.add("Read");
    }
    if (_accessModes.contains("Remove") 
        && !_accessModes.contains("Add")
        && !_accessModes.contains("Query")) {
      throw new PolicyCompilerException("Remove blackboard access implies " +
                                        "either Add or Query access");
    }
    if (_accessModes.contains("Change") 
        && !_accessModes.contains("Add")
        && !_accessModes.contains("Query")) {
      throw new PolicyCompilerException("Remove blackboard access implies " +
                                        "either Add or Query access");
    }
  }

  /**
   * This routine does the core work of constructing the policy defined by 
   * the Blackboard Access Policy.
   */
  public KAoSPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      Set    jenaAccessModes = new HashSet();
      ontology.verifySubClass(getActor(), 
                              UltralogActorConcepts.UltralogPlugins());
      // The stuff we gave to super is valid...
      initiateBuildPolicy(ontology);

      for (Iterator accessModesIt = _accessModes.iterator();
           accessModesIt.hasNext(); ) {
        String accessMode = (String) accessModesIt.next();
        String jenaAccessMode 
          =  EntityInstancesConcepts.EntityInstancesOwlURL()
                    + "BlackBoardAccess" + accessMode;
        ontology.verifyInstanceOf(jenaAccessMode, 
                                  UltralogEntityConcepts.BlackBoardAccessMode());
        _controls.addPropertyRangeInstance
              (UltralogActionConcepts.blackBoardAccessMode(), jenaAccessMode);
      }
      for (Iterator objectTypeIt = _objectTypes.iterator();
           objectTypeIt.hasNext(); ) {
        String objectType = (String) objectTypeIt.next();
        String jenaObjectClass = EntityInstancesConcepts.EntityInstancesOwlURL()
                                          + objectType;
        ontology.verifyInstanceOf(jenaObjectClass,
                                  UltralogEntityConcepts.BlackBoardObjects());
        _controls.addPropertyRangeInstance(
                           UltralogActionConcepts.blackBoardAccessObject(),
                           jenaObjectClass);
      }
      return _pb;
    } catch ( ClassNameNotSet e ) {
      throw new PolicyCompilerException(e);
    } catch ( RangeIsBasedOnAClass e) {
      throw new PolicyCompilerException(e);
    }
  }

}
