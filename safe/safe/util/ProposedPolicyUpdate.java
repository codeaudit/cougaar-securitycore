package safe.util;

import java.io.Serializable;
import java.util.List;

/**
 * Container for proposed policies
 */
public class ProposedPolicyUpdate implements Serializable
{
    /**
     * Constructor
     * 
     * @param updateType    The type of policy update. Valid types:
     *                      SET_POLICIES, ADD_POLICIES, CHANGE_POLICIES, or
     *                      REMOVE_POLICIES (from kaos.core.util.KAoSConstants)
     *                                              
     * @param policies      A list of policies (of type kaos.util.PolicyMsg) to
     *                      set/add/change/remove
     */
    public ProposedPolicyUpdate (String updateType,
                                 List policies)
    {
        _updateType = updateType;
        _policies = policies;
    }

    /**
     * Returns the type of policy update
     * 
     * @return updateType    The type of policy update. Valid types:
     *                       SET_POLICIES, ADD_POLICIES, CHANGE_POLICIES, or
     *                       REMOVE_POLICIES (from kaos.core.util.KAoSConstants)
     */
    public String getUpdateType()
    {
        return _updateType;
    }
    
    /**
     * Returns the list of policies
     * 
     * @return policies     A list of policies (of type kaos.util.PolicyMsg) to
     *                      set/add/change/remove
     */
    public List getPolicies()
    {
        return _policies;
    }
    
    private String _updateType;
    private List _policies;
}
