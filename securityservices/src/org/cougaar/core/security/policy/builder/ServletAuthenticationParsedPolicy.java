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
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.ontology.util.RangeIsBasedOnAClass;
import kaos.policy.util.DAMLPolicyBuilderImpl;

public class ServletAuthenticationParsedPolicy extends ParsedPolicy
{
  final String _servletClass
    = org.cougaar.core.security.policy.enforcers.ontology.jena.
        UltralogEntityConcepts._Servlet_;
  final String _authClass
    = org.cougaar.core.security.policy.enforcers.ontology.jena.
         UltralogEntityConcepts._AuthenticationLevel_;

  String _servletInstance;
  String _authInstance;

  public ServletAuthenticationParsedPolicy(String policyName,
                                           String auth,
                                           String servlet)
  {
    super(policyName, 
          3,
          false,
          kaos.ontology.jena.ActorConcepts._Person_,
          org.cougaar.core.security.policy.enforcers.ontology.jena.
          ActionConcepts._AccessAction_);
    _description = "All users must use " + auth + " authentication\n" +
                    "when accessing the servlet named " + servlet;
    _servletInstance = 
      org.cougaar.core.security.policy.enforcers.ontology.jena.
      EntityInstancesConcepts.EntityInstancesDamlURL
      + servlet;
    _authInstance = 
      org.cougaar.core.security.policy.enforcers.ontology.jena.
      EntityInstancesConcepts.EntityInstancesDamlURL + auth;
  }

  public DAMLPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      ontology.verifyInstanceOf(_authInstance, _authClass);
      ontology.verifyInstanceOf(_servletInstance, _servletClass);
      initiateBuildPolicy(ontology);
      _controls.addPropertyRangeInstance
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         UltralogActionConcepts._usedAuthenticationLevel_,
         _authInstance);
      _controls.addPropertyRangeInstance
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         UltralogActionConcepts._accessedServlet_,
         _servletInstance);

      return _pb;
    } catch (ClassNameNotSet e) {
      throw new PolicyCompilerException(e);
    } catch (RangeIsBasedOnAClass e) {
      throw new PolicyCompilerException(e);
    }
  }

}
