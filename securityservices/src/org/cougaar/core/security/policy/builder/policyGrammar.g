header {
  package org.cougaar.core.security.policy.builder;
  import org.cougaar.core.security.policy.builder.Main;
}

class P extends Parser;

policy
 [boolean bootpolicies]
 : "Policy" pn:TOKEN EQ LBRACK servletUserAccess[bootpolicies, pn] RBRACK
    ;

servletUserAccess
   [boolean bootpolicies, antlr.Token pn]
   { boolean m; }
    :   "A" "user" "in" "role" r:TOKEN m=modality 
        "access" "a" "servlet" "named" 
        n:TOKEN
        {System.out.println(
                "Boot policies = " + bootpolicies +
                "Policy name = " + pn.getText() +
                "User Role = " + r.getText() +
                " Modality = " + m +
                " servlet = " + n.getText()
            );
        Main.writeServletUserAccessPolicy(
                bootpolicies,
                pn.getText(),
                m,
                r.getText(),
                n.getText());
            }
    ;

modality returns [boolean m] { m = true; }
    : "can" { m = true; }
    | "cannot" { m = false; }
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
