package safe.enforcer;

import kaos.core.util.Msg;
import kaos.core.enforcer.Enforcer;

/**
 * Interface exposed by an Agent-level enforcer to the Guard.
 */
public interface AgentEnforcer extends Enforcer
{        
    /**
     * Returns the name of the agent the enforcer controls
     */
    public String getAgentName();
    
    /**
     * Returns the id of the agent the enforcer controls
     */
    public String getAgentId();
}
