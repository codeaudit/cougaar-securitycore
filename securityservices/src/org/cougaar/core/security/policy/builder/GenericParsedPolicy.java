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

