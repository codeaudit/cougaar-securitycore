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

header {
  package org.cougaar.core.security.policy.builder;

  import java.io.*;
  import java.util.*;

  import kaos.ontology.util.KAoSClassBuilderImpl;

  import org.cougaar.core.security.policy.builder.Main;
  import org.cougaar.core.security.policy.builder.PolicyBuilder;
  import org.cougaar.core.security.policy.builder.PolicyCompiler;
  import org.cougaar.core.security.policy.builder.PolicyCompilerException;
}

class P extends Parser;

policies
returns [List pl]
throws PolicyCompilerException
{   pl = new Vector();
    PolicyBuilder pb;}
    : ( pb = policy { pl.add(pb); })+
    ;

policy 
returns [PolicyBuilder pb]
throws PolicyCompilerException
{pb = null;}
    : "Policy" pn:TOKEN EQ LBRACK pb = innerPolicy[pn.getText()] RBRACK
    ;

innerPolicy [String pn]
returns [PolicyBuilder pb]
throws PolicyCompilerException
{  pb = null; }
    : pb = servletUserAccess[pn]
    | pb = servletAuthentication[pn]
    | pb = genericPolicy[pn]
    ;

/*
 * The generic policy is not as neat as it could be.  It essentially breaks 
 * into two sections, the construction of the DAMLPolicyBuilderImpl (done by
 * PolicyCompiler.genericPolicyInit()) and the construction of the KAoSClassBuilderImpl
 * (done by PolicyCompiler.genericPolicyStep() with lots of guidance from the parser.
 * This is a little ugly because the parser must hold these two pieces together and 
 * also guide the steps in the genericPolicyStep (there is one step for each target that is
 * parsed.  Not a good example of separating the work of the parser and the PolicyCompiler.
 */  

genericPolicy[String pn]
returns [PolicyBuilder pb]
throws PolicyCompilerException
{   pb = null;
    boolean modality = true; }        
    : "Priority" EQ priority:INT COMMA
      subject:URI "is" modality = genericAuth
        "to" "perform" action:URI "as" "long" "as"
  { pb = PolicyCompiler.genericPolicyInit(pn,
                                          PolicyCompiler.tokenToInt(priority),
                                          PolicyCompiler.tokenToURI(subject),
                                          modality,
                                          PolicyCompiler.tokenToURI(action));
        }
        LCURLY 
        genericTargets[PolicyCompiler.tokenToURI(action), pb]
        RCURLY
    ;

genericAuth
returns [boolean modality]
{  modality = true; }
    : "authorized" { modality = true; }
    | "not" "authorized" { modality = false; }
    ;

genericTargets[String action, PolicyBuilder pb]
throws PolicyCompilerException
    : genericTarget[action, pb] genericMoreTargets[action, pb]
    ;

genericMoreTargets[String action, PolicyBuilder pb]
throws PolicyCompilerException
    : 
    | "and" genericTarget[action, pb] genericMoreTargets[action, pb]
    ;

genericTarget[String action, PolicyBuilder pb]
throws PolicyCompilerException
{   String resType = null;
    boolean complementedTarget = false; }
    : "the" "value" "of" property:URI resType = genericRestrictionType
        complementedTarget=genericTargetModality
        genericRange[action, 
                     pb,
                     PolicyCompiler.tokenToURI(property), 
                     resType,
                     complementedTarget]
    ;

genericRestrictionType
returns [String resType]
{  resType = null; }
    : "is" "a" "subset" "of" "the"
        { resType = kaos.ontology.jena.PolicyConcepts._toClassRestriction; }
    | "contains" "at" "least" "one" "element" "from" "the"
        { resType = kaos.ontology.jena.PolicyConcepts._hasClassRestriction; }
    ;

genericTargetModality
returns [boolean complementedTarget]
{  complementedTarget = false; }
    : "set" { complementedTarget=false; }
    | "complement" "of" "the" "set" { complementedTarget=true; }
    ;

genericRange[String               action, 
             PolicyBuilder        pb,
             String               property,
             String               resType,
             boolean              complementedTarget]
throws PolicyCompilerException
    : range:URI 
  { PolicyCompiler.genericPolicyStep(action, 
                                     pb,
                                     property,
                                     resType,
                                     (Object) PolicyCompiler.tokenToURI(range),
                                     complementedTarget); }
    | { List instances = new Vector(); }
        LCURLY
        ( instance:URI 
            { try { 
                instances.add(PolicyCompiler.tokenToURI(instance)); 
              } catch (Exception e) {
                  throw new RuntimeException("shouldn't happen - " + 
                                             "see policyGrammar.g");
                } 
            } )*
        RCURLY
        { PolicyCompiler.genericPolicyStep(action, 
                                           pb,
                                           property,
                                           resType,
                                           (Object) instances,
                                           complementedTarget); }
    ;


/*
 * The Servlet Access template: (e.g. A user in role policyAdministrator is allowed to access a servlet named PolicyServlet)
 */
servletUserAccess [String pn] 
returns [PolicyBuilder pb]
throws PolicyCompilerException
{   boolean m; 
    pb = null; }
    :   "A" "user" "in" "role" r:TOKEN m=servletUserAccessModality 
        "access" "a" "servlet" "named" n:TOKEN
        {return 
           PolicyCompiler.servletUserAccessPolicy(
                pn,
                m,
                r.getText(),
                n.getText());
            }
    ;

servletUserAccessModality returns [boolean m] { m = true; }
    : "can" { m = true; }
    | "cannot" { m = false; }
   ;

/*
 * The servlet authentication servlet (e.g. All users must use CertificateSSL when accessing the servlet named PolicyServlet)
 */

servletAuthentication[String pn]
returns [PolicyBuilder pb]
throws PolicyCompilerException
{ pb = null; }
    : "All" "users" "must" "use" auth:TOKEN "authentication" "when"
        "accessing" "the" "servlet" "named" servlet:TOKEN
        { return
            PolicyCompiler.servletAuthentication(pn, 
                                                 auth.getText(), 
                                                 servlet.getText());
        }
    ;


class L extends Lexer;

// one-or-more letters followed by a newline
TOKEN:   ( 'a'..'z'|'A'..'Z' )+
    ;

INT : ( '0'..'9' )+ 
    ;

URI: '$' ( 'a'..'z'|'A'..'Z'|'/'|':'|'.'|'#')+
    ;

EQ: '='
    ;

LBRACK: '['
    ;

RBRACK: ']'
    ;

LCURLY: '{'
    ;

RCURLY: '}'
    ;

COMMA: ','
    ;

// Haven't gotten comments working yet...
//COMMENT: "/*" (~('/'))* '/'
//		{$setType(Token.SKIP);}	//ignore this token
//    ;


// whitespace
WS	:	(	' '
		|	'\t'
		|	'\r' '\n' { newline(); }
		|	'\n' { newline(); }
		)
		{$setType(Token.SKIP);}	//ignore this token
	;
