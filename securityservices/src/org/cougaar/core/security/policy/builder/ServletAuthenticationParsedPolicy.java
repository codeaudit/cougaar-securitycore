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

import kaos.ontology.util.AlreadyComplement;
import kaos.ontology.util.ClassNameNotSet;
import kaos.ontology.util.RangeIsBasedOnAClass;
import kaos.ontology.vocabulary.ActorConcepts;
import kaos.policy.util.KAoSPolicyBuilderImpl;

import org.cougaar.core.security.policy.ontology.EntityInstancesConcepts;
import org.cougaar.core.security.policy.ontology.UltralogActionConcepts;
import org.cougaar.core.security.policy.ontology.UltralogEntityConcepts;

public class ServletAuthenticationParsedPolicy extends ParsedAuthenticationPolicy
{
  final String _servletClass = UltralogEntityConcepts.Servlet();
  final String _authClass = UltralogEntityConcepts.AuthenticationLevel();

  String _servletInstance;
  Set    _authInstances;

  public ServletAuthenticationParsedPolicy(String policyName,
                                           Set    auths,
                                           String servlet)
  {
    super(policyName, 
          3,
          false,
          ActorConcepts.Person(),
          UltralogActionConcepts.ServletAccess());
    _description = "All users must use ";
    {
      Iterator authIt = auths.iterator();
      String auth = (String) authIt.next();
      _description += auth;
      while (authIt.hasNext()) {
        auth = (String) authIt.next();
        _description += ", " + auth;
      }
    }
    _description += " authentication\n" + "when accessing the servlet named " 
                          + servlet;
    _servletInstance = 
      EntityInstancesConcepts.EntityInstancesOwlURL()
      + servlet;

    _authInstances = new HashSet();
    for (Iterator authIt = auths.iterator(); authIt.hasNext();) {
      String auth = (String) authIt.next();
      _authInstances.add(EntityInstancesConcepts.EntityInstancesOwlURL() 
                         + auth);
    }
  }

  public KAoSPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      for (Iterator authIt = _authInstances.iterator(); authIt.hasNext();) {
        String auth = (String) authIt.next();
        ontology.verifyInstanceOf(auth, _authClass);
      }
      ontology.verifyInstanceOf(_servletInstance, _servletClass);

      initiateBuildPolicy(ontology);

      for (Iterator authIt = _authInstances.iterator(); authIt.hasNext();) {
        String auth = (String) authIt.next();
        _controls.addPropertyRangeInstance
          (UltralogActionConcepts.usedAuthenticationLevel(), auth);
      }
      _controls.makeRangeComplement
               (UltralogActionConcepts.usedAuthenticationLevel(), _authClass);

      _controls.addPropertyRangeInstance
               (UltralogActionConcepts.accessedServlet(), _servletInstance);

      return _pb;
    } catch (ClassNameNotSet e) {
      throw new PolicyCompilerException(e);
    } catch (RangeIsBasedOnAClass e) {
      throw new PolicyCompilerException(e);
    } catch (AlreadyComplement e) {
      throw new PolicyCompilerException(e);
    }
  }

}
