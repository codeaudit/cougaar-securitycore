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
import kaos.ontology.util.RangeIsBasedOnAClass;
import kaos.ontology.vocabulary.ActionConcepts;
import kaos.ontology.vocabulary.ActorConcepts;
import kaos.policy.util.KAoSPolicyBuilderImpl;

import org.cougaar.core.security.policy.ontology.EntityInstancesConcepts;
import org.cougaar.core.security.policy.ontology.UltralogActionConcepts;
import org.cougaar.core.security.policy.ontology.UltralogEntityConcepts;

public class MessageEncryptionParsedPolicy 
  extends ParsedAuthenticationPolicy
{
  String   _protectionLevel;
  String   _sourceAgentGroup;
  boolean  _sourceComplement;
  String   _destAgentGroup;
  boolean  _destComplement;

  public MessageEncryptionParsedPolicy(String  policyName,
                                       String  protectionLevel,
                                       String  sourceAgentGroup,
                                       boolean sourceComplement,
                                       String  destAgentGroup,
                                       boolean destComplement)
    throws PolicyCompilerException
  {
    super(policyName, 
          3,
          false,
          sourceAgentGroup,
          ActionConcepts.EncryptedCommunicationAction());
    _description = "Require " + protectionLevel + 
      " on all messages from members of " + 
      (sourceComplement ? "the complement of %" : "%")  + sourceAgentGroup + 
      " to all members of  " + (destComplement ? "the complement of %" : "%") +
      destAgentGroup;

    _protectionLevel = EntityInstancesConcepts.EntityInstancesOwlURL()
                                                            + protectionLevel;
    _sourceAgentGroup = sourceAgentGroup;
    _sourceComplement = sourceComplement;
    _destAgentGroup   = destAgentGroup;
    _destComplement   = destComplement;
  }


  public KAoSPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      ontology.verifyInstanceOf(_protectionLevel, 
                                UltralogEntityConcepts.UltralogEntityOwlURL()
                                + "ProtectionLevel");
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
      _controls.addPropertyRangeInstance(
                             UltralogActionConcepts.usedProtectionLevel(),
                             _protectionLevel);
      _controls.makeRangeComplement(
                            UltralogActionConcepts.usedProtectionLevel(),
                            UltralogEntityConcepts.UltralogEntityOwlURL()
                                + "ProtectionLevel");
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
