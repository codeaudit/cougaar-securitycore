/**
 * Last Modified by: $Author: srosset $
 * On: $Date: 2002-05-17 23:18:09 $
 */package safe.util;

import java.io.Serializable;
import java.util.Vector;

/**
 * A ConditionalPolicyMsg contains a set of conditions,
 * and a set of policies which apply when the conditions are true. 
 */
public class ConditionalPolicyMsg implements Serializable
{
    /**
     * Constructor
     * 
     * @param triggerConditions     Vector of TriggerCondition objects
     *                              which represents the conjunction of
     *                              TriggerConditions to evaluate
     * @param policies              Vector of kaos.core.util.PolicyMsg objects which
     *                              represent the policies to put in place if
     *                              the triggerConditions are true
     *                              
     */
    public ConditionalPolicyMsg (Vector triggerConditions, Vector policies)
    {
        _triggerConditions = triggerConditions;
        _policies = policies;
    }
    
    /**
     * @return      a vector of TriggerCondition objects which represent
     *              the conjunction of TriggerConditions to evaluate
     */
    public Vector getTriggerConditions()
    {
        return _triggerConditions;
    }
    
    /**
     * @return      a vector of kaos.core.util.PolicyMsg objects which represent the 
     *              policies to put in place if the triggerConditions are true
     */
    public Vector getPolicies()
    {
        return _policies;
    }
   
	public void setPolicies (Vector policies)
	{
		_policies = policies;
	}
					
    private Vector _triggerConditions;
    private Vector _policies;            
}
