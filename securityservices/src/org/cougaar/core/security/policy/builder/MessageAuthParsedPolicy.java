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

import kaos.ontology.util.AlreadyComplement;
import kaos.ontology.util.ClassNameNotSet;
import kaos.ontology.vocabulary.ActionConcepts;
import kaos.ontology.vocabulary.ActorConcepts;
import kaos.policy.util.KAoSPolicyBuilderImpl;


public class MessageAuthParsedPolicy 
  extends ParsedAuthenticationPolicy
{
  String   _sourceAgentGroup;
  boolean  _sourceComplement;
  String   _destAgentGroup;
  boolean  _destComplement;

  public MessageAuthParsedPolicy(String  policyName,
                                 boolean modality,
                                 String  sourceAgentGroup,
                                 boolean sourceComplement,
                                 String  destAgentGroup,
                                 boolean destComplement)
    throws PolicyCompilerException
  {
    super(policyName, 
          modality? 2 : 3,
          modality,
          sourceAgentGroup,
          ActionConcepts.EncryptedCommunicationAction());
    _description = (modality ? "Allow" : "Deny") + 
      " messages from members of " + 
      (sourceComplement ? "the complement of %" : "%")  + sourceAgentGroup + 
      " to all members of  " + (destComplement ? "the complement of %" : "%") 
      + destAgentGroup;

    _sourceAgentGroup = sourceAgentGroup;
    _sourceComplement = sourceComplement;
    _destAgentGroup   = destAgentGroup;
    _destComplement   = destComplement;
  }


  public KAoSPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      ontology.verifySubClass(_sourceAgentGroup, ActorConcepts.Agent());
      ontology.verifySubClass(_destAgentGroup,   ActorConcepts.Agent());

      initiateBuildPolicy(ontology);

      if (_sourceComplement) {
        _controls.makeRangeComplement(ActionConcepts.performedBy(), 
                                      ActorConcepts.Agent());
      }
      _controls.setPropertyRangeClass(ActionConcepts.hasDestination(), 
                                      _destAgentGroup);
      if (_destComplement) {
        _controls.makeRangeComplement(ActionConcepts.hasDestination(), 
                                      ActorConcepts.Agent());
      }
      return _pb;
    } catch (ClassNameNotSet e) {
      throw new PolicyCompilerException(e);
    } catch (AlreadyComplement e) {
      throw new PolicyCompilerException(e);
    }
  }

}
