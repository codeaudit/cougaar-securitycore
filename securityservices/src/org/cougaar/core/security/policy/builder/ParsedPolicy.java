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

import antlr.Token;

import java.util.*;

import jtp.ReasoningException;

import kaos.core.util.UniqueIdentifier;
import kaos.ontology.util.JTPStringFormatUtils;
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.ontology.util.ValueNotSet;
import kaos.policy.util.DAMLPolicyBuilderImpl;
import kaos.policy.util.SpecifiedModalityTypeNotExists;

public abstract class ParsedPolicy 
{
  protected String  _policyName;
  protected int     _priority;
  protected boolean _modality;
  protected String  _action;
  protected String  _actor;
  protected String  _description;
  
  protected DAMLPolicyBuilderImpl    _pb;
  protected KAoSClassBuilderImpl _controls;

  ParsedPolicy(String  policyName,
               int     priority,
               boolean modality,
               String  actor,
               String  action)
  {
    _policyName     = policyName;
    _priority = priority;
    _modality = modality;
    _actor    = actor;
    _action   = action;
  }



  public static String tokenToURI(Token u)
    throws PolicyCompilerException
  {
    String str = u.getText();
    try {
      str =  str.substring(1, str.length());
      return "http://ontology.coginst.uwf.edu/" + str;
    } catch (IndexOutOfBoundsException e) {
      PolicyCompilerException pe 
        = new PolicyCompilerException("Malformed URI: " + str + " on line " +
                                      u.getLine());
      throw pe;
    }
  }

  public static int tokenToInt(Token u)
    throws PolicyCompilerException
  {
    String str = u.getText();
    try {
      return Integer.parseInt(str);
    } catch (NumberFormatException e) {
      PolicyCompilerException pe 
        = new PolicyCompilerException("Coding error: Parsing token " + 
                                      str + " on line: " + str);
      throw pe;
    }
  }

  

  public abstract DAMLPolicyBuilderImpl
    buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException;
  
  /**
   * This function is called when the parser of the policy has
   * determined the basics about the policy:
   *    policyName - the name of the policy
   *    priority - the priority of the policy
   *    subject - the actor performing the action that the
   *                     policy controls
   *    modality - whether the policy allows or denies an event
   *    action - the action type that the policy controls
   * The parser has not yet determined the other constraints that
   * govern when the policy is applicable.  E.g. the policy may only
   * control communication actions when the destination address is a
   * particular subject.  The constraints about the "destination
   * address" are introduced later.
   *
   */

  protected void initiateBuildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      _pb = new DAMLPolicyBuilderImpl();
      ontology.verifySubClass(_actor, 
                              kaos.ontology.jena.ActorConcepts._Actor_);
      ontology.verifySubClass(_action,  
                              kaos.ontology.jena.ActionConcepts._Action_);

      try {
        _pb.setPolicyIDAndModalityType("#policy-grammarGenerated-" 
                                       + UniqueIdentifier.GenerateUID(), 
                                       (_modality ?
                                        kaos.ontology.jena.PolicyConcepts.
                                        _PosAuthorizationPolicy_               : 
                                        kaos.ontology.jena.PolicyConcepts.
                                        _NegAuthorizationPolicy_));
      } catch (SpecifiedModalityTypeNotExists e) {
        RuntimeException fatal 
          = new RuntimeException("This should be impossible - CODING ERROR");
        fatal.initCause(e);
        throw fatal;
      }
      _pb.setPolicyName(_policyName);
      _pb.setPriority(_priority);
      _pb.setPolicyDesc(_description);
      _pb.setHasSiteOfEnforcement(kaos.ontology.jena.PolicyConcepts.
                                 policyDamlURL
                                 + "AnySite");

      // build the KAoSClassBuilderImp (e.g. the targets)
      _controls = new KAoSClassBuilderImpl(_action);
      _controls.setPropertyRangeClass
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         ActionConcepts._performedBy_,
         _actor);
      _pb.setControlsActionClass(_controls);
    } catch (Exception e) {
      PolicyCompilerException pe 
        = new PolicyCompilerException("trouble building generic policy named "
                                      + _policyName);
      pe.initCause(e);
      throw pe;
    }

  }

  /**
   * This function is called to introduce some additional constraints
   * on the applicability of the policy.  It is called after
   * genericPolicyInit().  For example, genericPolicyInit() may
   * introduce a policy that says that 
   *    "members of community X are allowed to send messages if ...".
   * Now in genericPolicyStep we introduce some of the constraints
   * given by the "...".  Such a constraint might say "if the message
   * is sent to community Y."
   */

  public void addTargetToBuild(OntologyConnection ontology,
                               ParsedTarget       target)
    throws PolicyCompilerException
  {
    String jtpAction = JTPStringFormatUtils.convertStringToJTPFormat(_action);
    String jtpProperty 
      = JTPStringFormatUtils.convertStringToJTPFormat(target.getProperty());
    String fullRange = null;
    try {
      String jtpFullRange = ontology.getRangeOnPropertyForClass(jtpAction, 
                                                                 jtpProperty);
      fullRange =JTPStringFormatUtils.convertJTPFormatToString(jtpFullRange);
    } catch (Exception e) {
      throw new PolicyCompilerException(e);
    }

    /*
     * First some checks
     */
    try {
      List applicableJtpProperties
        = ontology.getPropertiesApplicableTo(jtpAction);
      if (!applicableJtpProperties.contains(jtpProperty)) {
        throw new PolicyCompilerException(target.getProperty()
                                          + " is not applicable to " 
                                          + _action);
      }
      if (target.getRange() instanceof List) {
        List instances = (List) target.getRange();
        for (Iterator instanceIt = instances.iterator();
             instanceIt.hasNext();) {
          String instance = (String) instanceIt.next();
          String jtpInstance 
            = JTPStringFormatUtils.convertStringToJTPFormat(instance);
          ontology.verifyInstanceOf(instance, fullRange);
        }
      } else {
        ontology.verifySubClass((String) target.getRange(), fullRange);
      }
    } catch (ReasoningException re) {
      throw new PolicyCompilerException(re);
    }

    try {
      if (target.getRange() instanceof List) {
        List instances = (List) target.getRange();
        for (Iterator instanceIt = instances.iterator();
             instanceIt.hasNext(); ) {
          String instance = (String) instanceIt.next();
          _controls.addPropertyRangeInstance(target.getProperty(), instance);
        }
      } else {
        _controls.setPropertyRangeClass(target.getProperty(), 
                                        (String) target.getRange(), 
                                        target.getRestrictionType());
      }
      if (target.getIsComplement()) {
        _controls.makeRangeComplement(target.getProperty(), fullRange);
      }
    } catch (Exception e) {
      PolicyCompilerException pe  
        = new PolicyCompilerException("Error working on policy named " +
                                      _policyName);
      pe.initCause(e);
      throw pe;
    }

  }

  

}
