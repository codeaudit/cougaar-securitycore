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

import java.io.*;
import java.util.*;

import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.ontology.util.JTPStringFormatUtils;

import org.cougaar.core.security.policy.builder.PolicyBuilder;


public class PolicyCompiler
{
  public static List compile(String file)
    throws IOException, PolicyCompilerException
  {
    FileInputStream fis = new FileInputStream(file);
    List result;
    try {
      L lexer = new L(new DataInputStream(fis));
      P parser = new P(lexer);
      result = parser.policies();
    } catch (Exception e) {
      PolicyCompilerException pce 
        = new PolicyCompilerException("Compile failed");
      pce.initCause(e);
      throw pce;
    } finally {
      fis.close();
    }
    return result;
  }

  public static String tokenToURI(Token u)
    throws PolicyCompilerException
  {
    String str = u.getText();
    try {
      return str.substring(1, str.length());
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
        = new PolicyCompilerException("Shouldn't happen: Parsing token " + 
                                      str + " on line: " + str);
      throw pe;
    }
  }



  /*
   * Other checks should be included later (does the action go with the 
   * subject?) 
   */

  /**
   * This function is called when the parser of the policy has
   * determined the basics about the policy:
   *   @param policyName - the name of the policy
   *   @param priority - the priority of the policy
   *   @param subject - the actor performing the action that the
   *                     policy controls
   *   @param modality - whether the policy allows or denies an event
   *   @param action - the action type that the policy controls
   * The parser has not yet determined the other constraints that
   * govern when the policy is applicable.  E.g. the policy may only
   * control communication actions when the destination address is a
   * particular subject.  The constraints about the "destination
   * address" are introduced when the parser calls genericPolicyStep
   *
   * Roughly speaking, genericPolicyInit() constructs the
   * PolicyBuilder and the genericPolicyStep() calls construct the
   * KAoSClassBuilderImp.  The two are connected by the parser (sad
   * but true).
   */
  public static PolicyBuilder genericPolicyInit(String  policyName,
                                                int     priority,
                                                String  subject,
                                                boolean modality,
                                                String  action)
    throws PolicyCompilerException
  {
    try {
      PolicyBuilder pb = new PolicyBuilder();
      pb.assertSubClass(subject, kaos.ontology.jena.ActorConcepts._Actor_);
      pb.assertSubClass(action,  kaos.ontology.jena.ActionConcepts._Action_);
      pb.setPolicyModality(modality);
      pb.setPolicyName(policyName);
      pb.setPolicyDesc(policyName);
      pb.setPriority(priority);
      pb.setHasSiteOfEnforcement(kaos.ontology.jena.PolicyConcepts.
                                 policyDamlURL
                                 + "AnySite");
      return pb;
    } catch (Exception e) {
      PolicyCompilerException pe 
        = new PolicyCompilerException("trouble building generic policy named "
                                      + policyName);
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
   *
   * Roughly speaking, genericPolicyInit() constructs the
   * PolicyBuilder and the genericPolicyStep() calls construct the
   * KAoSClassBuilderImp.  The two are connected by the parser (sad
   * but true).
   */
  public static void genericPolicyStep(String               action,
                                       PolicyBuilder        pb,
                                       KAoSClassBuilderImpl controls,
                                       String               role,
                                       String               resType,
                                       String               range)
    throws PolicyCompilerException
  {
    ;
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
   *
   * Roughly speaking, genericPolicyInit() constructs the
   * PolicyBuilder and the genericPolicyStep() calls construct the
   * KAoSClassBuilderImp.  The two are connected by the parser (sad
   * but true).
   */
  public static void genericPolicyStep(String               action,
                                       PolicyBuilder        pb,
                                       KAoSClassBuilderImpl controls,
                                       String               role,
                                       String               resType,
                                       List                 instances)
    throws PolicyCompilerException
  {
    ;
  }
                                                
                                                

  public static PolicyBuilder servletUserAccessPolicy(String policyName,
                                                      boolean modality,
                                                      String userRole,
                                                      String servlet)
    throws PolicyCompilerException
  {
    String userClass = 
      org.cougaar.core.security.policy.enforcers.ontology.jena.
      ActorClassesConcepts.ActorClassesDamlURL
      + userRole;
    String servletInstance = 
      org.cougaar.core.security.policy.enforcers.ontology.jena.
      EntityInstancesConcepts.EntityInstancesDamlURL
      + servlet;

    PolicyBuilder pb = new PolicyBuilder();
    pb.assertSubClass(userClass, kaos.ontology.jena.ActorConcepts._Person_);
    pb.assertInstanceOf(servletInstance, 
                        org.cougaar.core.security.policy.enforcers.ontology.jena.
                        UltralogEntityConcepts._Servlet_);
    System.out.println("Assertions passed");
    try {
      pb.setPolicyModality(modality);
      pb.setPolicyName(policyName);
      pb.setPolicyDesc("A user in role " + userRole + 
                       (modality ? " can" : " cannot")
                       + " access the servlet named " + servlet);
      pb.setPriority(modality ? 2 : 3);
      pb.setHasSiteOfEnforcement(kaos.ontology.jena.PolicyConcepts.
                                 policyDamlURL
                                 + "AnySite");
      KAoSClassBuilderImpl controls = 
        new KAoSClassBuilderImpl
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         ActionConcepts._AccessAction_);
      controls.setPropertyRangeClass
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         ActionConcepts._performedBy_,
         userClass);
      controls.addPropertyRangeInstance
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         UltralogActionConcepts._accessedServlet_,
         servletInstance);
      pb.setControlsActionClass(controls);
      return pb;
    } catch (Exception e) {
      PolicyCompilerException pce
        = new PolicyCompilerException("Compiler Failure in Servlet Policy");
      pce.initCause(e);
      throw pce;
    }
  }

  public static PolicyBuilder servletAuthentication(String policyName,
                                                    String auth,
                                                    String servlet)
    throws PolicyCompilerException
  {
    String authInstance = 
      org.cougaar.core.security.policy.enforcers.ontology.jena.
      EntityInstancesConcepts.EntityInstancesDamlURL + auth;
    String servletInstance = 
      org.cougaar.core.security.policy.enforcers.ontology.jena.
      EntityInstancesConcepts.EntityInstancesDamlURL
      + servlet;

    PolicyBuilder pb = new PolicyBuilder();
    pb.assertInstanceOf(servletInstance, 
                        org.cougaar.core.security.policy.enforcers.ontology.jena.
                        UltralogEntityConcepts._Servlet_);
    pb.assertInstanceOf(authInstance, 
                        org.cougaar.core.security.policy.enforcers.ontology.jena.
                        UltralogEntityConcepts._AuthenticationLevel_);
    try {
      pb.setPolicyModality(false);
      pb.setPolicyName(policyName);
      pb.setPolicyDesc("All users must use " + auth + " authentication\n" +
                       "when accessing the servlet named " + servlet);
      pb.setPriority(3);
      pb.setHasSiteOfEnforcement(kaos.ontology.jena.PolicyConcepts.
                                 policyDamlURL
                                 + "AnySite");
      KAoSClassBuilderImpl controls = 
        new KAoSClassBuilderImpl
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         ActionConcepts._AccessAction_);
      controls.setPropertyRangeClass
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         ActionConcepts._performedBy_,
         kaos.ontology.jena.ActorConcepts._Person_);
      controls.addPropertyRangeInstance
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         UltralogActionConcepts._usedAuthenticationLevel_,
         authInstance);
      controls.addPropertyRangeInstance
        (org.cougaar.core.security.policy.enforcers.ontology.jena.
         UltralogActionConcepts._accessedServlet_,
         servletInstance);
      pb.setControlsActionClass(controls);
      return pb;
    } catch (Exception e) {
      PolicyCompilerException pce
        = new PolicyCompilerException("Compiler Failure in Servlet Policy");
      pce.initCause(e);
      throw pce;
    }
  }



}