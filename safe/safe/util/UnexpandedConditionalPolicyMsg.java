/**
 * Last Modified by: $Author: srosset $
 * On: $Date: 2002-05-17 23:18:09 $
 */package safe.util;

import java.io.Serializable;

/**
 * This class acts as a container for a ConditionalPolicyMsg before it has
 * been expanded by the PolicyExpanderPlugIn
 */
public class UnexpandedConditionalPolicyMsg implements Serializable
{
	public UnexpandedConditionalPolicyMsg (ConditionalPolicyMsg msg)
	{
		_msg = msg;		
	}
	
	public ConditionalPolicyMsg getConditionalPolicyMsg()
	{
		return _msg;
	}
	
	private ConditionalPolicyMsg _msg;
}
				