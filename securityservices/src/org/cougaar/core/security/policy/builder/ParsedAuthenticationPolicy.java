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

import kaos.ontology.vocabulary.PolicyConcepts;

/**
 * When we are only interested in positive and negative authentication policies,
 * the modality of a policy is a boolean value.  This class allows callers to 
 * consider modality as a boolean even though there is a class of policies 
 * (obligation policies) that have other values for modality.
 */

abstract class ParsedAuthenticationPolicy
  extends ParsedPolicy
{
  boolean _authModality = false;

  ParsedAuthenticationPolicy(String  policyName,
                             int     priority,
                             boolean modality,
                             String  actor,
                             String  action)
  {
    super(policyName, 
          priority, 
          booleanModalityToString(modality),
          actor,
          action);
    _authModality = modality;
  }

  private static String  booleanModalityToString(boolean modality)
  {
    return modality ? PolicyConcepts.PosAuthorizationPolicy()    : 
                      PolicyConcepts.NegAuthorizationPolicy()    ;
  }

  public boolean getAuthModality()
  {
    return _authModality;
  }
}
