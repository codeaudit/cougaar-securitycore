// $ANTLR 2.7.1: "policyGrammar.g" -> "P.java"$

  package org.cougaar.core.security.policy.builder;

  import java.io.*;
  import java.util.*;

  import kaos.ontology.util.KAoSClassBuilderImpl;

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
		PolicyBuilder pb;
		
		Token  pn = null;
		pb = null;
		
		try {      // for error handling
			match(LITERAL_Policy);
			pn = LT(1);
			match(TOKEN);
			match(EQ);
			match(LBRACK);
			pb=innerPolicy(pn.getText());
			match(RBRACK);
		}
		catch (RecognitionException ex) {
			reportError(ex);
			consume();
			consumeUntil(_tokenSet_1);
		}
		return pb;
	}
	
	public final PolicyBuilder  innerPolicy(
		String pn
	) throws RecognitionException, TokenStreamException, PolicyCompilerException {
		PolicyBuilder pb;
		
		pb = null;
		
		try {      // for error handling
			switch ( LA(1)) {
			case LITERAL_A:
			{
				pb=servletUserAccess(pn);
				break;
			}
			case LITERAL_All:
			{
				pb=servletAuthentication(pn);
				break;
			}
			case LITERAL_Priority:
			{
				pb=genericPolicy(pn);
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
		return pb;
	}
	
	public final PolicyBuilder  servletUserAccess(
		String pn
	) throws RecognitionException, TokenStreamException, PolicyCompilerException {
		PolicyBuilder pb;
		
		Token  r = null;
		Token  n = null;
		boolean m; 
		pb = null;
		
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
		return pb;
	}
	
	public final PolicyBuilder  servletAuthentication(
		String pn
	) throws RecognitionException, TokenStreamException, PolicyCompilerException {
		PolicyBuilder pb;
		
		Token  auth = null;
		Token  servlet = null;
		pb = null;
		
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
		return pb;
	}
	
	public final PolicyBuilder  genericPolicy(
		String pn
	) throws RecognitionException, TokenStreamException, PolicyCompilerException {
		PolicyBuilder pb;
		
		Token  priority = null;
		Token  subject = null;
		Token  action = null;
		pb = null;
		boolean modality = true;
		
		try {      // for error handling
			match(LITERAL_Priority);
			match(EQ);
			priority = LT(1);
			match(INT);
			match(COMMA);
			subject = LT(1);
			match(TOKEN);
			match(LITERAL_is);
			modality=genericAuth();
			match(LITERAL_to);
			match(LITERAL_perform);
			action = LT(1);
			match(TOKEN);
			match(LITERAL_as);
			match(LITERAL_long);
			match(LITERAL_as);
			pb = PolicyCompiler.genericPolicyInit(pn,
			PolicyCompiler.tokenToInt(priority),
			PolicyCompiler.tokenToURI(subject),
			modality,
			PolicyCompiler.tokenToURI(action));
			KAoSClassBuilderImpl controls = 
			new KAoSClassBuilderImpl(PolicyCompiler.tokenToURI(action));
			
			match(LCURLY);
			genericTargets(PolicyCompiler.tokenToURI(action), pb, controls);
			match(RCURLY);
			pb.setControlsActionClass(controls);
		}
		catch (RecognitionException ex) {
			reportError(ex);
			consume();
			consumeUntil(_tokenSet_2);
		}
		return pb;
	}
	
	public final boolean  genericAuth() throws RecognitionException, TokenStreamException {
		boolean modality;
		
		modality = true;
		
		try {      // for error handling
			switch ( LA(1)) {
			case LITERAL_authorized:
			{
				match(LITERAL_authorized);
				modality = true;
				break;
			}
			case LITERAL_not:
			{
				match(LITERAL_not);
				match(LITERAL_authorized);
				modality = false;
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
		return modality;
	}
	
	public final void genericTargets(
		String action, PolicyBuilder pb, KAoSClassBuilderImpl controls
	) throws RecognitionException, TokenStreamException, PolicyCompilerException {
		
		
		try {      // for error handling
			{
			_loop10:
			do {
				if ((LA(1)==LITERAL_the)) {
					genericTarget(action, pb, controls);
				}
				else {
					break _loop10;
				}
				
			} while (true);
			}
		}
		catch (RecognitionException ex) {
			reportError(ex);
			consume();
			consumeUntil(_tokenSet_4);
		}
	}
	
	public final void genericTarget(
		String action, PolicyBuilder pb, KAoSClassBuilderImpl controls
	) throws RecognitionException, TokenStreamException, PolicyCompilerException {
		
		Token  role = null;
		String resType = null;
		
		try {      // for error handling
			match(LITERAL_the);
			match(LITERAL_value);
			match(LITERAL_of);
			role = LT(1);
			match(URI);
			resType=genericRestrictionType();
			match(LITERAL_of);
			genericRange(action, 
                          pb,
                          controls, 
                          PolicyCompiler.tokenToURI(role), 
                          resType);
		}
		catch (RecognitionException ex) {
			reportError(ex);
			consume();
			consumeUntil(_tokenSet_5);
		}
	}
	
	public final String  genericRestrictionType() throws RecognitionException, TokenStreamException {
		String resType;
		
		resType = null;
		
		try {      // for error handling
			switch ( LA(1)) {
			case LITERAL_is:
			{
				match(LITERAL_is);
				match(LITERAL_a);
				match(LITERAL_subset);
				resType = kaos.ontology.jena.PolicyConcepts._toClassRestriction;
				break;
			}
			case LITERAL_contains:
			{
				match(LITERAL_contains);
				match(LITERAL_at);
				match(LITERAL_least);
				match(LITERAL_one);
				resType = kaos.ontology.jena.PolicyConcepts._hasClassRestriction;
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
			consumeUntil(_tokenSet_6);
		}
		return resType;
	}
	
	public final void genericRange(
		String               action, 
             PolicyBuilder        pb,
             KAoSClassBuilderImpl controls,
             String               role,
             String               resType
	) throws RecognitionException, TokenStreamException, PolicyCompilerException {
		
		Token  range = null;
		Token  instance = null;
		
		try {      // for error handling
			switch ( LA(1)) {
			case URI:
			{
				range = LT(1);
				match(URI);
				PolicyCompiler.genericPolicyStep(action, 
				pb,
				controls,
				role,
				resType,
				PolicyCompiler.tokenToURI(range));
				break;
			}
			case LCURLY:
			{
				List instances = new Vector();
				match(LCURLY);
				{
				_loop15:
				do {
					if ((LA(1)==URI)) {
						instance = LT(1);
						match(URI);
						try { 
						instances.add(PolicyCompiler.tokenToURI(instance)); 
						} catch (Exception e) {
						throw new RuntimeException("shouldn't happen - " + 
						"see policyGrammar.g");
						} 
						
					}
					else {
						break _loop15;
					}
					
				} while (true);
				}
				match(RCURLY);
				PolicyCompiler.genericPolicyStep(action, 
				pb,
				controls,
				role,
				resType,
				instances);
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
			consumeUntil(_tokenSet_5);
		}
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
			consumeUntil(_tokenSet_7);
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
		"\"Priority\"",
		"INT",
		"COMMA",
		"\"is\"",
		"\"to\"",
		"\"perform\"",
		"\"as\"",
		"\"long\"",
		"LCURLY",
		"RCURLY",
		"\"authorized\"",
		"\"not\"",
		"\"the\"",
		"\"value\"",
		"\"of\"",
		"URI",
		"\"a\"",
		"\"subset\"",
		"\"contains\"",
		"\"at\"",
		"\"least\"",
		"\"one\"",
		"\"A\"",
		"\"user\"",
		"\"in\"",
		"\"role\"",
		"\"access\"",
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
	private static final long _tokenSet_4_data_[] = { 262144L, 0L };
	public static final BitSet _tokenSet_4 = new BitSet(_tokenSet_4_data_);
	private static final long _tokenSet_5_data_[] = { 2359296L, 0L };
	public static final BitSet _tokenSet_5 = new BitSet(_tokenSet_5_data_);
	private static final long _tokenSet_6_data_[] = { 8388608L, 0L };
	public static final BitSet _tokenSet_6 = new BitSet(_tokenSet_6_data_);
	private static final long _tokenSet_7_data_[] = { 34359738368L, 0L };
	public static final BitSet _tokenSet_7 = new BitSet(_tokenSet_7_data_);
	
	}
