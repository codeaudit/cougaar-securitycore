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

    import java.util.*;
    import kaos.ontology.vocabulary.ActorConcepts;
    import kaos.ontology.vocabulary.PolicyConstants;
    import org.cougaar.core.security.policy.ontology.EntityInstancesConcepts;
    import org.cougaar.core.security.policy.ontology.GroupInstancesConcepts;
    import org.cougaar.core.security.policy.ontology.ULOntologyNames;
    import org.cougaar.core.security.policy.ontology.UltralogEntityConcepts;
    import org.cougaar.core.security.policy.ontology.UltralogGroupConcepts;
}

class PolicyParser extends Parser;

policyFile
returns [ParsedPolicyFile ppf]
throws PolicyCompilerException
{   ppf = new ParsedPolicyFile();
    ParsedPolicy pp;  
    Set policyNames = new HashSet();
}
    :   ( declaration[ppf] )*
        ( pp = policy 
            {   ppf.addPolicy(pp); 
                if (policyNames.contains(pp.getPolicyName())) {
                  System.out.println("Duplicate policy name: " + 
                                                  pp.getPolicyName());
                  System.out.println("Only matters with build command or"
                                     + " commit without --dm option");
                } else {
                  policyNames.add(pp.getPolicyName());
                }
             })*
    ;

declaration[ParsedPolicyFile ppf]
throws PolicyCompilerException
    : setprefix[ppf]
    | "Delete" policyName:TOKEN
        { ppf.addDeletion(ParsedPolicyFile.tokenToText(policyName)); }
    | "Agent" agentName:TOKEN
        { ppf.declareInstance(ULOntologyNames.agentPrefix 
                                + ParsedPolicyFile.tokenToText(agentName),
                              ActorConcepts.Agent()); }
    | "UserRole" userRoleName:TOKEN
        { ppf.declareInstance(GroupInstancesConcepts.GroupInstancesOwlURL()
                              + ParsedPolicyFile.tokenToText(userRoleName)
                              + "Role",
                              UltralogGroupConcepts.Role()); }
    | "Servlet" servletName:TOKEN
        { ppf.declareInstance(EntityInstancesConcepts.EntityInstancesOwlURL()
                              + ParsedPolicyFile.tokenToText(servletName),
                              UltralogEntityConcepts.Servlet()); }
    | "PlugInRole" pluginRoleName:TOKEN
        {   String pluginRoleText
                       = ParsedPolicyFile.tokenToText(pluginRoleName);
            /* for backwards compatibility - delete else case soon */
            if (!pluginRoleText.endsWith("Role")) {
                pluginRoleText += "Role";
            } else {
                System.out.println("Deprecated usage - use PluginRole "
                                   + pluginRoleText
                                      .substring(0,pluginRoleText.length() -4));
            }
            ppf.declareInstance(EntityInstancesConcepts.EntityInstancesOwlURL()
                              + pluginRoleText,
                              UltralogEntityConcepts.PlugInRoles()); }
    | "BlackBoardObject" blackBoardObjectName:TOKEN
        { ppf.declareInstance(
                    ULOntologyNames.blackboardObjectPrefix + 
                           ParsedPolicyFile.tokenToText(blackBoardObjectName),
                    UltralogEntityConcepts.BlackBoardObjects()); }
    | { Set agents = null; }
        "AgentGroup" agentGroup:TOKEN EQ LCURLY agents =tokenList RCURLY
        {  ppf.declareAgentGroup(ParsedPolicyFile.tokenToText(agentGroup), 
                                 agents); }
    ;

setprefix[ParsedPolicyFile ppf]
throws PolicyCompilerException
    : "PolicyPrefix" EQ prefix:URI
        {  
      if (prefix.getText().startsWith("$")) {
        throw new PolicyCompilerException("Policy prefix must begin with %");
      }
      ppf.setPrefix(ParsedPolicyFile.identifierToURI(prefix));
         }
    ;

policy 
returns [ParsedPolicy pp]
throws PolicyCompilerException
{pp = null;}
    : "Policy" pn:TOKEN EQ LBRACK 
        pp = innerPolicy[ParsedPolicyFile.tokenToText(pn)] RBRACK
        conditionalAddendum[pp]
    ;

conditionalAddendum[ParsedPolicy pp]
throws PolicyCompilerException
    : "when" "operating" "mode" EQ mode:TOKEN
        { pp.setConditionalMode(ParsedPolicyFile.tokenToText(mode)); }
    |
    ;

innerPolicy [String pn]
returns [ParsedPolicy pp]
throws PolicyCompilerException
{  pp = null; }
    : "GenericTemplate"               pp = genericPolicy[pn]
    | "AuditTemplate"                 pp = audit[pn]
    | "BlackboardTemplate"            pp = blackboardPolicy[pn]
    | "MessageAuthTemplate"           pp=  messageAuthPolicy[pn]
    | "MessageEncryptionTemplate"     pp=  messageEncryptionPolicy[pn]
    | "ServletAuthenticationTemplate" pp = servletAuthentication[pn]
    | "ServletUserAccessTemplate"     pp = servletUserAccess[pn]
    ;


genericPolicy[String pn]
returns [ParsedPolicy pp]
throws PolicyCompilerException
{   boolean modality; 
    pp = null; }
    : "Priority" EQ priority:INT COMMA
      subject:URI "is" modality = genericAuth
        "to" "perform" action:URI "as" "long" "as"
  { GenericParsedPolicy gpp 
          = new GenericParsedPolicy(pn,
                                    ParsedPolicyFile.identifierToInt(priority),
                                    modality,
                                    ParsedPolicyFile.identifierToURI(subject),
                                    ParsedPolicyFile.identifierToURI(action));
        }
        genericTargets[gpp]
        { pp = gpp; }
    ;

genericAuth
returns [boolean modality]
{  modality = true; }
    : "authorized" { modality = true; }
    | "not" "authorized" { modality = false; }
    ;

genericTargets[GenericParsedPolicy pp]
throws PolicyCompilerException
    : genericTarget[pp] genericMoreTargets[pp]
    ;

genericMoreTargets[GenericParsedPolicy pp]
throws PolicyCompilerException
    : 
    | "and" genericTarget[pp] genericMoreTargets[pp]
    ;

genericTarget[GenericParsedPolicy pp]
throws PolicyCompilerException
{   String resType = null;
    boolean complementedTarget = false; }
    : "the" "value" "of" property:URI resType = genericRestrictionType
        complementedTarget=genericTargetModality
        genericRange[pp,
                     ParsedPolicyFile.identifierToURI(property), 
                     resType,
                     complementedTarget]
    ;

genericRestrictionType
returns [String resType]
{  resType = null; }
    : "is" "a" "subset" "of" "the"
        { resType = PolicyConstants._toClassRestriction; }
    | "contains" "at" "least" "one" "element" "from" "the"
        { resType = PolicyConstants._hasClassRestriction; }
    ;

genericTargetModality
returns [boolean complementedTarget]
{  complementedTarget = false; }
    : "set" { complementedTarget=false; }
    | "complement" "of" "the" "set" { complementedTarget=true; }
    ;

genericRange[GenericParsedPolicy  pp,
             String               property,
             String               resType,
             boolean              complementedTarget]
throws PolicyCompilerException
    : range:URI 
  { pp.addTarget(property,
                resType,
                (Object) ParsedPolicyFile.identifierToURI(range),
                complementedTarget); }
    | { List instances = new Vector(); }
        LCURLY
        ( instance:URI 
            { try { 
                instances.add(ParsedPolicyFile.identifierToURI(instance)); 
              } catch (Exception e) {
                  throw new RuntimeException("shouldn't happen - " + 
                                             "see policyGrammar.g");
                } 
            } )*
        RCURLY
        { pp.addTarget(property,
                       resType,
                       (Object) instances,
                       complementedTarget); }
    ;


audit[String pn]
returns [ParsedPolicy pp]
throws PolicyCompilerException
{   pp = null;
    String userRole = null;
    Set servletNames = null;
}   : "Require" "audit" "for" "all" "accesses" "to" 
        servletNames=auditServlet  userRole = auditUsers
        { pp = new AuditParsedPolicy(pn, userRole, servletNames); }
    ;


/*
 * returns a list of servlets and null if the list is supposed to be all
 * servlets.
 */
auditServlet
returns [Set servletNames]
{  servletNames = null; }
    : "servlet" servletNames = tokenList
    | "all" "servlets"
    ;

auditUsers
returns [String userRole]
{   userRole = null; }
    : "by" "users" "in" "role" role:TOKEN
        { userRole = ParsedPolicyFile.tokenToText(role); }
    |
    ;


/*
 * The Blackboard policy template: (e.g. A plugin in the role OpPlan can
 * add, remove, change, query objects of type OpPlan on the blackboard.
 */

blackboardPolicy[String pn]
returns [ParsedPolicy pp]
throws PolicyCompilerException
{   pp=null;
    Set accessModes = null; 
    Set objectTypes = null; }
    : "A" "PlugIn" "in" "the" "role" pluginRole:TOKEN "can" 
        accessModes=tokenList "objects" "of" "type" 
        objectTypes = tokenList
        { pp = new BlackboardParsedPolicy(
                                pn,
                                ParsedPolicyFile.tokenToText(pluginRole), 
                                accessModes, 
                                objectTypes); }
    ;



messageAuthPolicy[String pn]
returns [ParsedPolicy pp]
throws PolicyCompilerException
{  pp = null; 
   boolean modality         = true;
   boolean sourceComplement = false;
   boolean destComplement  =  false;}
    :  modality = messageAuthModality "messages" "from" "members" 
        "of" sourceComplement = messageComplemented sourceAgentGroup:URI "to"
        "members" "of" destComplement = messageComplemented 
        destAgentGroup:URI
        { pp = new MessageAuthParsedPolicy(
                     pn,
                     modality,
                     ParsedPolicyFile.identifierToURI(sourceAgentGroup),
                     sourceComplement,
                     ParsedPolicyFile.identifierToURI(destAgentGroup),
                     destComplement); }
    ;       

messageAuthModality
returns [boolean modality]
{   modality = true;  }
    : "Allow" { modality = true;  }
    | "Deny"  { modality = false; }
    ;

/*
 * The message encryption template (Require NSAAprovedProtection on all 
 * messages from members of agentGroupX to members of the complement of 
 * agentGroupY
 */
messageEncryptionPolicy[String pn]
returns [ParsedPolicy pp]
throws PolicyCompilerException
{  pp = null; 
   boolean sourceComplement = false;
   boolean destComplement  =  false;}
    :  "Require" protectLevel:TOKEN "on" "all" "messages" "from" "members" 
        "of" sourceComplement = messageComplemented sourceAgentGroup:URI "to"
        "members" "of" destComplement = messageComplemented 
        destAgentGroup:URI
        { pp = new MessageEncryptionParsedPolicy(
                     pn,
                     ParsedPolicyFile.tokenToText(protectLevel),
                     ParsedPolicyFile.identifierToURI(sourceAgentGroup),
                     sourceComplement,
                     ParsedPolicyFile.identifierToURI(destAgentGroup),
                     destComplement); }
    ;       

messageComplemented
returns [boolean complemented]
{  complemented = false; }
    : "the" "complement" "of"
        { complemented = true;}
    |   { complemented = false;}
    ;


/*
 * The servlet authentication servlet (e.g. All users must use CertificateSSL 
 * when accessing the servlet named PolicyServlet)
 */

servletAuthentication[String pn]
returns [ParsedPolicy pp]
throws PolicyCompilerException
{   pp = null; 
    Set auth = new HashSet(); }
    : "All" "users" "must" "use" auth = tokenList "authentication" "when"
        "accessing" "the" "servlet" "named" servlet:TOKEN
        { pp = 
            new ServletAuthenticationParsedPolicy(
                pn, 
                auth, 
                ParsedPolicyFile.tokenToText(servlet));
        }
    ;



/*
 * The Servlet Access template: (e.g. A user in role policyAdministrator is 
 * allowed to access a servlet named PolicyServlet) 
 */
servletUserAccess [String pn] 
returns [ParsedPolicy pp]
throws PolicyCompilerException
{   boolean m; 
    pp = null; }
    :   "A" "user" "in" "role" r:TOKEN m=servletUserAccessModality 
        "access" "a" "servlet" "named" n:TOKEN
        {pp = new ServletUserParsedPolicy(
                pn,
                m,
                ParsedPolicyFile.tokenToText(r),
                ParsedPolicyFile.tokenToText(n));
            }
    ;

servletUserAccessModality returns [boolean m] { m = true; }
    : "can" { m = true; }
    | "cannot" { m = false; }
   ;



/*
 * tokenList is used to represent a list of tokens.  It returns a set
 * consisting of the tokens.
 */
tokenList
returns [Set items]
{   items = null; }
    : item:TOKEN items=moreTokenList
        { // System.out.println("Working on token list item " + item);
          items.add(ParsedPolicyFile.tokenToText(item)); }
    ;

moreTokenList
returns [Set items]
{   items = null; }
    : COMMA item:TOKEN items = moreTokenList
        { // System.out.println("Working on token list item " + item);
          items.add(ParsedPolicyFile.tokenToText(item)); }
    |
        { // System.out.println("Found way to end of the token list");
            items = new HashSet(); }
    ;


class PolicyLexer extends Lexer;
options {
    charVocabulary='\3'..'\377'; 
}

// one-or-more letters followed by a newline
TOKEN  
    :   ( 'a'..'z'|'A'..'Z')
        ( 'a'..'z'|'A'..'Z'|'0'..'9'|'/'|':'|'.'|'-'|'_' )*
    |   '"' (~'"')+ '"'
    ;


//
// I have implemented two different types of URL
// In the "%" version, everything after the % represents the URI being 
// represented.  In the $ version, the $ is a shorthand for the URI prefix
//     http://ontology.ihmc.us/
// Thus for example 
//         $Action.owl#hasDestination 
// represents the URL
//       http://ontology.ihmc.us/Action.owl#hasDestination
//
URI: '$'  ( 'a'..'z'|'A'..'Z'|'0'..'9'|'/'|':'|'.'|'#'|'-'|'_')+ 
    | '%' ( 'a'..'z'|'A'..'Z'|'0'..'9'|'/'|':'|'.'|'#'|'-'|'_')+ 
    ;


INT : ( '0'..'9' )+ 
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


// whitespace
WS	:	(	' '
		|	'\t'
		|	'\r' '\n' { newline(); }
		|	'\n' { newline(); }
		)
		{$setType(Token.SKIP);}	//ignore this token
	;


// The newline() call ensures that line numbers are correct in policy files
// that have comments.
COMMENT: '#' (~'\n')* '\n'
		{$setType(Token.SKIP);  newline(); }	//ignore this token
    ;

