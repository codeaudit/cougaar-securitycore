// $ANTLR 2.7.1: "policyGrammar.g" -> "P.java"$

  package org.cougaar.core.security.policy.builder;
  import org.cougaar.core.security.policy.builder.Main;

import antlr.TokenBuffer;
import antlr.TokenStreamException;
import antlr.TokenStreamIOException;
import antlr.ANTLRException;
import antlr.LLkParser;
import antlr.Token;
import antlr.TokenStream;
import antlr.RecognitionException;
import antlr.NoViableAltException;
import antlr.MismatchedTokenException;
import antlr.SemanticException;
import antlr.ParserSharedInputState;
import antlr.collections.impl.BitSet;
import antlr.collections.AST;
import antlr.ASTPair;
import antlr.collections.impl.ASTArray;

public class P extends antlr.LLkParser
       implements PTokenTypes
 {

protected P(TokenBuffer tokenBuf, int k) {
  super(tokenBuf,k);
  tokenNames = _tokenNames;
}

public P(TokenBuffer tokenBuf) {
  this(tokenBuf,1);
}

protected P(TokenStream lexer, int k) {
  super(lexer,k);
  tokenNames = _tokenNames;
}

public P(TokenStream lexer) {
  this(lexer,1);
}

public P(ParserSharedInputState state) {
  super(state,1);
  tokenNames = _tokenNames;
}

	public final void policy(
		boolean bootpolicies
	) throws RecognitionException, TokenStreamException {
		
		Token  pn = null;
		
		try {      // for error handling
			match(LITERAL_Policy);
			pn = LT(1);
			match(TOKEN);
			match(EQ);
			match(LBRACK);
			servletUserAccess(bootpolicies, pn);
			match(RBRACK);
		}
		catch (RecognitionException ex) {
			reportError(ex);
			consume();
			consumeUntil(_tokenSet_0);
		}
	}
	
	public final void servletUserAccess(
		boolean bootpolicies, antlr.Token pn
	) throws RecognitionException, TokenStreamException {
		
		Token  r = null;
		Token  n = null;
		boolean m;
		
		try {      // for error handling
			match(LITERAL_A);
			match(LITERAL_user);
			match(LITERAL_in);
			match(LITERAL_role);
			r = LT(1);
			match(TOKEN);
			m=modality();
			match(LITERAL_access);
			match(LITERAL_a);
			match(LITERAL_servlet);
			match(LITERAL_named);
			n = LT(1);
			match(TOKEN);
			System.out.println(
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
		catch (RecognitionException ex) {
			reportError(ex);
			consume();
			consumeUntil(_tokenSet_1);
		}
	}
	
	public final boolean  modality() throws RecognitionException, TokenStreamException {
		boolean m;
		
		m = true;
		
		try {      // for error handling
			switch ( LA(1)) {
			case LITERAL_can:
			{
				match(LITERAL_can);
				m = true;
				break;
			}
			case LITERAL_cannot:
			{
				match(LITERAL_cannot);
				m = false;
				break;
			}
			default:
			{
				throw new NoViableAltException(LT(1), getFilename());
			}
			}
		}
		catch (RecognitionException ex) {
			reportError(ex);
			consume();
			consumeUntil(_tokenSet_2);
		}
		return m;
	}
	
	
	public static final String[] _tokenNames = {
		"<0>",
		"EOF",
		"<2>",
		"NULL_TREE_LOOKAHEAD",
		"\"Policy\"",
		"TOKEN",
		"EQ",
		"LBRACK",
		"RBRACK",
		"\"A\"",
		"\"user\"",
		"\"in\"",
		"\"role\"",
		"\"access\"",
		"\"a\"",
		"\"servlet\"",
		"\"named\"",
		"\"can\"",
		"\"cannot\"",
		"WS"
	};
	
	private static final long _tokenSet_0_data_[] = { 2L, 0L };
	public static final BitSet _tokenSet_0 = new BitSet(_tokenSet_0_data_);
	private static final long _tokenSet_1_data_[] = { 256L, 0L };
	public static final BitSet _tokenSet_1 = new BitSet(_tokenSet_1_data_);
	private static final long _tokenSet_2_data_[] = { 8192L, 0L };
	public static final BitSet _tokenSet_2 = new BitSet(_tokenSet_2_data_);
	
	}
