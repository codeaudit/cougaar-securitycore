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

import java.util.*;

import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.policy.util.DAMLPolicyBuilderImpl;


public class GenericParsedPolicy extends ParsedPolicy
{
  private List _parsedTargets;

  public GenericParsedPolicy(String  policyName,
                             int     priority,
                             boolean modality,
                             String  subject,
                             String  action)
  {
    super(policyName, priority, modality, subject, action);
    _parsedTargets = new Vector();
    _description   = policyName;
  }

  public void addTarget(String  property,
                        String  resType,
                        Object  range,
                        boolean isComplement)
  {
    _parsedTargets.add(new ParsedTarget(property, 
                                        resType, 
                                        range, 
                                        isComplement));
  }

  public DAMLPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    initiateBuildPolicy(ontology);
    for (Iterator parsedTargetIt = _parsedTargets.iterator();
         parsedTargetIt.hasNext();) {
      ParsedTarget parsedTarget = (ParsedTarget) parsedTargetIt.next();
      addTargetToBuild(ontology, parsedTarget);
    }
    return _pb;
  }

}

