// $ANTLR 2.7.1: "policyGrammar.g" -> "P.java"$

  package org.cougaar.core.security.policy.builder;

  import java.io.*;
  import java.util.*;

  import org.cougaar.core.security.policy.builder.Main;
  import org.cougaar.core.security.policy.builder.PolicyBuilder;
  import org.cougaar.core.security.policy.builder.PolicyCompiler;
  import org.cougaar.core.security.policy.builder.PolicyCompilerException;

public interface PTokenTypes {
	int EOF = 1;
	int NULL_TREE_LOOKAHEAD = 3;
	int LITERAL_Policy = 4;
	int TOKEN = 5;
	int EQ = 6;
	int LBRACK = 7;
	int RBRACK = 8;
	int LITERAL_A = 9;
	int LITERAL_user = 10;
	int LITERAL_in = 11;
	int LITERAL_role = 12;
	int LITERAL_access = 13;
	int LITERAL_a = 14;
	int LITERAL_servlet = 15;
	int LITERAL_named = 16;
	int LITERAL_can = 17;
	int LITERAL_cannot = 18;
	int LITERAL_All = 19;
	int LITERAL_users = 20;
	int LITERAL_must = 21;
	int LITERAL_use = 22;
	int LITERAL_authentication = 23;
	int LITERAL_when = 24;
	int LITERAL_accessing = 25;
	int LITERAL_the = 26;
	int WS = 27;
}
