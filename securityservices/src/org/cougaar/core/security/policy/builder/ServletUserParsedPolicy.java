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

import kaos.ontology.util.ClassNameNotSet;
import kaos.ontology.util.RangeIsBasedOnAClass;
import kaos.policy.util.DAMLPolicyBuilderImpl;

import org.cougaar.core.security.policy.enforcers.ontology.jena.
  UltralogEntityConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.
  ActionConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.
  EntityInstancesConcepts;

public class ServletUserParsedPolicy extends ParsedAuthenticationPolicy
{
   
  final String _servletClass = UltralogEntityConcepts._Servlet_;

  String _userClass;
  String _servletInstance;

  public ServletUserParsedPolicy(String  policyName,
                                 boolean modality,
                                 String  userRole,
                                 String  servletName)
    throws PolicyCompilerException
  {
    super(policyName, 
          modality ? 2 : 3,
          modality,
          PolicyUtils.personActorClassPrefix + userRole,
          ActionConcepts._AccessAction_);
    _description = "A user in role " + userRole + (modality? " can":" cannot")
                         + "  access a servlet named " + servletName;
    _userClass = PolicyUtils.personActorClassPrefix + userRole;
    _servletInstance 
      = EntityInstancesConcepts.EntityInstancesDamlURL + servletName;
  }

/**
   * This routine does the core work of constructing the policy defined by 
   * the servlet access policy.
   */

  public DAMLPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      ontology.verifySubClass(_userClass, 
                              kaos.ontology.jena.ActorConcepts._Person_);
      ontology.verifyInstanceOf(_servletInstance, _servletClass);
      initiateBuildPolicy(ontology);
      _controls.addPropertyRangeInstance
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         UltralogActionConcepts._accessedServlet_,
         _servletInstance);
      return _pb;
    } catch ( ClassNameNotSet e ) {
      throw new PolicyCompilerException(e);
    } catch ( RangeIsBasedOnAClass e) {
      throw new PolicyCompilerException(e);
    }
  }

}
