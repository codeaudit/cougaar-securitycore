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

import javax.agent.service.directory.DirectoryFailure;

import jtp.ReasoningException;

import kaos.core.util.UniqueIdentifier;
import kaos.ontology.management.UnknownConceptException;
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.ontology.util.QueryFailure;
import kaos.ontology.vocabulary.ActionConcepts;
import kaos.ontology.vocabulary.ActorConcepts;
import kaos.ontology.vocabulary.PolicyConcepts;
import kaos.policy.util.KAoSPolicyBuilderImpl;
import kaos.policy.util.SpecifiedModalityTypeNotExists;

public abstract class ParsedPolicy 
{
  private   String  _policyPrefix;
  private   String  _policyName;
  private   int     _priority;
  private   String  _modality;
  private   String  _action;
  private   String  _actor;
  protected String  _description;
  private   String  _conditionalMode;
  
  protected KAoSPolicyBuilderImpl    _pb;
  protected KAoSClassBuilderImpl _controls;

  ParsedPolicy(String  policyName,
               int     priority,
               String  modality,
               String  actor,
               String  action)
  {
    _policyPrefix    = "";
    _policyName      = policyName;
    _priority        = priority;
    _modality        = modality;
    _actor           = actor;
    _action          = action;
    _conditionalMode = null;
  }

  /*
   * Get and set methods
   */

  public String getPolicyName()
  {
    return _policyPrefix + _policyName;
  }

  public void setPolicyPrefix(String prefix)
  {
    _policyPrefix = prefix;
  }

  public String getActor()
  {
    return _actor;
  }

  public String getAction()
  {
    return _action;
  }

  public String getDescription()
  {
    return _description;
  }

  public String getConditionalMode()
  {
    return _conditionalMode;
  }

  public void setConditionalMode(String mode)
    throws PolicyCompilerException
  {
    if (!(mode.equals("LOW")) && !(mode.equals("HIGH"))) {
      throw new PolicyCompilerException("Unknown conditional mode " + mode);
    }
    _conditionalMode = mode;
  }


  public abstract KAoSPolicyBuilderImpl
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
    boolean actorIsInstance = false;
    try {
      String policyId = null;
      _pb = new KAoSPolicyBuilderImpl();
      actorIsInstance = checkActorIsInstance(ontology);
      ontology.verifySubClass(_action, ActionConcepts.Action());

      try {
        policyId="#policy-grammarGenerated-" + UniqueIdentifier.GenerateUID();
        _pb.setPolicyIDAndModalityType(policyId, _modality);
      } catch (SpecifiedModalityTypeNotExists e) {
        RuntimeException fatal 
          = new RuntimeException("This should be impossible - CODING ERROR");
        fatal.initCause(e);
        throw fatal;
      }
      _pb.setPolicyName(getPolicyName());
      _pb.setPriority(_priority);
      _pb.setPolicyDesc(_description);
      _pb.setHasSiteOfEnforcement(PolicyConcepts.AnySite());

      // build the KAoSClassBuilderImp (e.g. the targets)
      _controls = new KAoSClassBuilderImpl(policyId.substring(1) + _action);
      _controls.addImmediateBaseClass(_action);
      if (actorIsInstance) {
        _controls.addPropertyRangeInstance(ActionConcepts.performedBy(), 
                                           _actor);
      } else {
        _controls.setPropertyRangeClass(ActionConcepts.performedBy(), _actor);
      }
      _pb.setControlsActionClass(_controls);
    } catch (PolicyCompilerException pce) {
      throw pce;
    } catch (Exception e) {
      PolicyCompilerException pe 
        = new PolicyCompilerException("trouble building generic policy named "
                                      + _policyName);
      pe.initCause(e);
      throw pe;
    }
  }

  protected boolean checkActorIsInstance(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      ontology.verifySubClass(_actor, ActorConcepts.Actor());
      return false;
    } catch (PolicyCompilerException pceClass) {
      try {
        ontology.verifyInstanceOf(_actor, ActorConcepts.Actor());
        return true;
      } catch (PolicyCompilerException pceInstance) {
        PolicyCompilerException pce = 
          new PolicyCompilerException(_actor + 
                                      " is not a subclass or instance of " +
                                      "the kaos actor class");
        pce.initCause(pceInstance);
        throw pce;
      }
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
    String fullRange = null;
    try {
      fullRange= ontology.getRangeOnPropertyForClass(_action, 
                                                     target.getProperty());
    } catch (Exception e) {
      throw new PolicyCompilerException(e);
    }

    /*
     * First some checks
     */
    try {
      List applicableJtpProperties
        = ontology.getPropertiesApplicableTo(_action);
      if (!applicableJtpProperties.contains(target.getProperty())) {
        throw new PolicyCompilerException(target.getProperty()
                                          + " is not applicable to " 
                                          + _action);
      }
    } catch (UnknownConceptException uce) {
      throw new PolicyCompilerException(uce);
    } catch (QueryFailure qf) {
      throw new PolicyCompilerException(qf);
    } catch (DirectoryFailure df) {
      throw new PolicyCompilerException(df);
    }

    if (target.getRange() instanceof List) {
      List instances = (List) target.getRange();
      for (Iterator instanceIt = instances.iterator();
           instanceIt.hasNext();) {
        String instance = (String) instanceIt.next();
        ontology.verifyInstanceOf(instance, fullRange);
      }
    } else {
      ontology.verifySubClass((String) target.getRange(), fullRange);
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
