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

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import kaos.ontology.jena.ActorConcepts;
import kaos.ontology.util.ClassNameNotSet;
import kaos.ontology.util.RangeIsBasedOnAClass;
import kaos.policy.util.DAMLPolicyBuilderImpl;


import org.cougaar.core.security.policy.enforcers.ontology.jena.
  ActionConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.
  EntityInstancesConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.
  UltralogActionConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.
  UltralogEntityConcepts;

class AuditParsedPolicy extends ParsedAuthenticationPolicy
{
  Set _servlets;

  public AuditParsedPolicy(String policyName,
                           String userRole,
                           Set     servletNames)
  {
    super(policyName,
          3,
          false,
          userRole == null ? ActorConcepts._Person_
                           : PolicyUtils.personActorClassPrefix + userRole,
          ActionConcepts._AccessAction_);
    if (servletNames != null) {
      _servlets = new HashSet();
      for (Iterator  servletIt = servletNames.iterator(); 
           servletIt.hasNext();) {
        String servletInstance = (String) servletIt.next();
        _servlets.add(EntityInstancesConcepts.EntityInstancesDamlURL 
                      + servletInstance);
      }
    } else {
      _servlets = null;
    }
    buildDescription(userRole, servletNames);
  }

  private void buildDescription(String userRole, Set servletNames)
  {
    _description = "Require audit for all accesses to ";

    if (servletNames != null) {
      _description += "servlet ";
      Iterator servletIt = servletNames.iterator();
      String servletInstance = (String) servletIt.next();
      _description += servletInstance;
      while (servletIt.hasNext()) {
        servletInstance = (String) servletIt.next();
        _description += ", " + servletInstance;
      }
    } else {
      _description += "all servlets";
    }

    if (userRole != null) {
      _description += " by users in role " + userRole;
    }
  }

  public DAMLPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      ontology.verifySubClass(getActor(), ActorConcepts._Person_);
      initiateBuildPolicy(ontology);

      if (_servlets != null) {
        for (Iterator servletIt = _servlets.iterator(); servletIt.hasNext();) {
          String servletInstance = (String) servletIt.next();
          ontology.verifyInstanceOf(servletInstance, 
                                    UltralogEntityConcepts._Servlet_);
          _controls.addPropertyRangeInstance
                                (UltralogActionConcepts._accessedServlet_,
                                 servletInstance);
        }
      }
      _controls.addPropertyRangeInstance
                       (UltralogActionConcepts._usedAuditLevel_, 
                        EntityInstancesConcepts.EntityInstancesDamlURL +
                        "NoAudit");
      return _pb;
    } catch ( ClassNameNotSet e ) {
      throw new PolicyCompilerException(e);
    } catch ( RangeIsBasedOnAClass e) {
      throw new PolicyCompilerException(e);
    }
  }

}
