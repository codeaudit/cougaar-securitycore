// $ANTLR 2.7.1: "policyGrammar.g" -> "P.java"$

  package org.cougaar.core.security.policy.builder;

  import java.io.*;
  import java.util.*;

  import org.cougaar.core.security.policy.builder.Main;
  import org.cougaar.core.security.policy.builder.PolicyBuilder;
  import org.cougaar.core.security.policy.builder.PolicyCompiler;
  import org.cougaar.core.security.policy.builder.PolicyCompilerException;

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

	public final List  policies() throws RecognitionException, TokenStreamException, PolicyCompilerException {
		List pl;
		
		pl = new Vector();
		PolicyBuilder pb;
		
		try {      // for error handling
			{
			int _cnt3=0;
			_loop3:
			do {
				if ((LA(1)==LITERAL_Policy)) {
					pb=policy();
					pl.add(pb);
				}
				else {
					if ( _cnt3>=1 ) { break _loop3; } else {throw new NoViableAltException(LT(1), getFilename());}
				}
				
				_cnt3++;
			} while (true);
			}
		}
		catch (RecognitionException ex) {
			reportError(ex);
			consume();
			consumeUntil(_tokenSet_0);
		}
		return pl;
	}
	
	public final PolicyBuilder  policy() throws RecognitionException, TokenStreamException, PolicyCompilerException {
		PolicyBuilder p;
		
		Token  pn = null;
		p = null;
		
		try {      // for error handling
			match(LITERAL_Policy);
			pn = LT(1);
			match(TOKEN);
			match(EQ);
			match(LBRACK);
			p=innerPolicy(pn.getText());
			match(RBRACK);
		}
		catch (RecognitionException ex) {
			reportError(ex);
			consume();
			consumeUntil(_tokenSet_1);
		}
		return p;
	}
	
	public final PolicyBuilder  innerPolicy(
		String pn
	) throws RecognitionException, TokenStreamException, PolicyCompilerException {
		PolicyBuilder p;
		
		p = null;
		
		try {      // for error handling
			switch ( LA(1)) {
			case LITERAL_A:
			{
				p=servletUserAccess(pn);
				break;
			}
			case LITERAL_All:
			{
				p=servletAuthentication(pn);
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
		return p;
	}
	
	public final PolicyBuilder  servletUserAccess(
		String pn
	) throws RecognitionException, TokenStreamException, PolicyCompilerException {
		PolicyBuilder p;
		
		Token  r = null;
		Token  n = null;
		boolean m; 
		p = null;
		
		try {      // for error handling
			match(LITERAL_A);
			match(LITERAL_user);
			match(LITERAL_in);
			match(LITERAL_role);
			r = LT(1);
			match(TOKEN);
			m=servletUserAccessModality();
			match(LITERAL_access);
			match(LITERAL_a);
			match(LITERAL_servlet);
			match(LITERAL_named);
			n = LT(1);
			match(TOKEN);
			return 
			PolicyCompiler.servletUserAccessPolicy(
			pn,
			m,
			r.getText(),
			n.getText());
			
		}
		catch (RecognitionException ex) {
			reportError(ex);
			consume();
			consumeUntil(_tokenSet_2);
		}
		return p;
	}
	
	public final PolicyBuilder  servletAuthentication(
		String pn
	) throws RecognitionException, TokenStreamException, PolicyCompilerException {
		PolicyBuilder p;
		
		Token  auth = null;
		Token  servlet = null;
		p = null;
		
		try {      // for error handling
			match(LITERAL_All);
			match(LITERAL_users);
			match(LITERAL_must);
			match(LITERAL_use);
			auth = LT(1);
			match(TOKEN);
			match(LITERAL_authentication);
			match(LITERAL_when);
			match(LITERAL_accessing);
			match(LITERAL_the);
			match(LITERAL_servlet);
			match(LITERAL_named);
			servlet = LT(1);
			match(TOKEN);
			return
			PolicyCompiler.servletAuthentication(pn, 
			auth.getText(), 
			servlet.getText());
			
		}
		catch (RecognitionException ex) {
			reportError(ex);
			consume();
			consumeUntil(_tokenSet_2);
		}
		return p;
	}
	
	public final boolean  servletUserAccessModality() throws RecognitionException, TokenStreamException {
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
			consumeUntil(_tokenSet_3);
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
		"\"All\"",
		"\"users\"",
		"\"must\"",
		"\"use\"",
		"\"authentication\"",
		"\"when\"",
		"\"accessing\"",
		"\"the\"",
		"WS"
	};
	
	private static final long _tokenSet_0_data_[] = { 2L, 0L };
	public static final BitSet _tokenSet_0 = new BitSet(_tokenSet_0_data_);
	private static final long _tokenSet_1_data_[] = { 18L, 0L };
	public static final BitSet _tokenSet_1 = new BitSet(_tokenSet_1_data_);
	private static final long _tokenSet_2_data_[] = { 256L, 0L };
	public static final BitSet _tokenSet_2 = new BitSet(_tokenSet_2_data_);
	private static final long _tokenSet_3_data_[] = { 8192L, 0L };
	public static final BitSet _tokenSet_3 = new BitSet(_tokenSet_3_data_);
	
	}
