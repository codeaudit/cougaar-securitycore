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

import org.cougaar.core.security.policy.enforcers.ontology.jena.EntityInstancesConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.UltralogActionConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.UltralogEntityConcepts;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import kaos.ontology.jena.ActionConcepts;
import kaos.ontology.jena.ActorConcepts;
import kaos.ontology.util.AlreadyComplement;
import kaos.ontology.util.ClassNameNotSet;
import kaos.ontology.util.RangeIsBasedOnAClass;
import kaos.policy.util.DAMLPolicyBuilderImpl;


import org.cougaar.core.security.policy.enforcers.ontology.jena.EntityInstancesConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.UltralogActionConcepts;
import org.cougaar.core.security.policy.enforcers.ontology.jena.UltralogEntityConcepts;

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
          ActionConcepts._EncryptedCommunicationAction_);
    _description = "Require " + protectionLevel + 
      " on all messages from members of " + 
      (sourceComplement ? "the complement of %" : "%")  + sourceAgentGroup + 
      " to all members of  " + (destComplement ? "the complement of %" : "%") +
      destAgentGroup;

    _protectionLevel = EntityInstancesConcepts.EntityInstancesDamlURL
                                                            + protectionLevel;
    _sourceAgentGroup = sourceAgentGroup;
    _sourceComplement = sourceComplement;
    _destAgentGroup   = destAgentGroup;
    _destComplement   = destComplement;
  }


  public DAMLPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      ontology.verifyInstanceOf(_protectionLevel, 
                                UltralogEntityConcepts.UltralogEntityDamlURL
                                + "ProtectionLevel");
      ontology.verifySubClass(_sourceAgentGroup, ActorConcepts._Agent_);
      ontology.verifySubClass(_destAgentGroup,   ActorConcepts._Agent_);

      initiateBuildPolicy(ontology);

      if (_sourceComplement) {
        _controls.makeRangeComplement(ActionConcepts._performedBy_, 
                                      ActorConcepts._Agent_);
      }
      _controls.setPropertyRangeClass(ActionConcepts._hasDestination_, 
                                      _destAgentGroup);
      if (_destComplement) {
        _controls.makeRangeComplement(ActionConcepts._hasDestination_, 
                                      ActorConcepts._Agent_);
      }
      _controls.addPropertyRangeInstance(
                             UltralogActionConcepts._usedProtectionLevel_,
                             _protectionLevel);
      _controls.makeRangeComplement(
                            UltralogActionConcepts._usedProtectionLevel_,
                            UltralogEntityConcepts.UltralogEntityDamlURL
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
