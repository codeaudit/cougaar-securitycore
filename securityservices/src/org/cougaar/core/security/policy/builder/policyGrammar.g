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
returns [PolicyBuilder p]
throws PolicyCompilerException
{p = null;}
    : "Policy" pn:TOKEN EQ LBRACK p = innerPolicy[pn.getText()] RBRACK
    ;

innerPolicy [String pn]
returns [PolicyBuilder p]
throws PolicyCompilerException
{  p = null; }
    : p = servletUserAccess[pn]
    | p = servletAuthentication[pn]
    ;

servletUserAccess [String pn] 
returns [PolicyBuilder p]
throws PolicyCompilerException
{   boolean m; 
    p = null; }
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

servletAuthentication[String pn]
returns [PolicyBuilder p]
throws PolicyCompilerException
{ p = null; }
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

EQ: '='
    ;

LBRACK: '['
    ;

RBRACK: ']'
    ;



// whitespace
WS	:	(	' '
		|	'\t'
		|	'\r' '\n' { newline(); }
		|	'\n' { newline(); }
		)
		{$setType(Token.SKIP);}	//ignore this token
	;
