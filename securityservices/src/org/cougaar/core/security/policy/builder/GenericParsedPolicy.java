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

import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import kaos.ontology.vocabulary.PolicyConstants;
import kaos.policy.util.KAoSPolicyBuilderImpl;


public class GenericParsedPolicy extends ParsedAuthenticationPolicy
{
  private List _parsedTargets;

  /**
   * Construct the generic parsed policy.  The only that is unusual
   * here is the fact that the _description is incomplete when the
   * constructor is done.  It is completed when all the targets are
   * added.
   *
   * This description code is ugly - is there a way to use antlr to
   * avoid this?
   */ 
  public GenericParsedPolicy(String  policyName,
                             int     priority,
                             boolean modality,
                             String  subject,
                             String  action)
  {
    super(policyName, priority, modality, subject, action);
    _parsedTargets = new Vector();
    _description = 
      "Priority  = " + priority + ",\n"
      + subject + " is " 
      + (modality?"authorized":"not authorized")
      + " to perform\n" + action + "\n";
  }

  public void addTarget(String  property,
                        String  resType,
                        Object  range,
                        boolean isComplement)
  {
    boolean firstTarget = _parsedTargets.isEmpty();

    _parsedTargets.add(new ParsedTarget(property, 
                                        resType, 
                                        range, 
                                        isComplement));

    if (!firstTarget) {
      _description += "\t\tand\n";
    } else {
      _description += " as long as ";
    }
    _description += "the value of " + property + "\n";
    if (resType.equals(PolicyConstants._toClassRestriction)) {
      _description += "is a subset of the";
    } else {
      _description += "contains at least one of the";
    }
    if (isComplement) {
      _description += " complement of the set\n";
    } else {
      _description += " set\n";
    }
    if (range instanceof String) {
      _description += (String) range + "\n";
    } else if (range instanceof List) {
      List instances = (List) range;
      boolean firstTime = true;
      _description += "{";
      for (Iterator instancesIt = instances.iterator();
           instancesIt.hasNext();) {
        String instance = (String) instancesIt.next();
        if (firstTime) {
          firstTime=false;
        } else {
          _description += ",\n ";
        }
        _description += instance;
      }
      _description += "}\n";
    }
  }

  public KAoSPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
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

