package safe.util;

import org.cougaar.core.plugin.SimplePlugin;

import kaos.core.util.Msg;
import kaos.core.util.UniqueIdentifier;
import kaos.core.guard.GuardRetriever;
import kaos.core.guard.Guard;

import safe.enforcer.AgentEnforcer;
import safe.enforcer.NodeEnforcer;

import java.util.List;

/**
 * The PseudoBinderPlugin registers two enforcers with the guard,
 * one node-level and one agent-level. They register with type
 * "pseudoNodeBinder" and "pseudoAgentBinder", respectively.
 * The enforcers simply print policy messages to stdout when they receive
 * them.
 * 
 * This PlugIn is meant for purposes of testing and demonstration only.
 */
public class PseudoBinderPlugin extends SimplePlugin {
    
    public void setupSubscriptions()
    {
        Guard guard = GuardRetriever.getGuard();
        guard.registerEnforcer(new PseudoNodeBinder(), "pseudoNodeBinder");                               
        guard.registerEnforcer(new PseudoAgentBinder(), "pseudoAgentBinder");
    }
    
    public void execute()
    {
	}
    
    private class PseudoAgentBinder implements AgentEnforcer
    {
        public PseudoAgentBinder()
        {
            _agentId = System.getProperty("safe.util.PseudoBinderPlugIn.agentId");
            if (_agentId == null) {
                throw new NullPointerException("property safe.util.PseudoBinderPlugIn.agentId is not set");
            }
        }
        
        public String getName() {
            return "";
        }
        
        public void receivePolicyUpdate (String updateType,
                                         List policies) 
        {
            System.out.println("PseudoAgentBinder::receivePolicyUpdate");
            System.out.println("updateType = " + updateType);
            System.out.println(policies);           
        }
        
        public String getAgentName()
        {
            return "PseudoAgentBinder";
        }
        
        public String getAgentId()
        {
            return _agentId;
        }
    }
    
    private class PseudoNodeBinder implements NodeEnforcer
    {        
        public PseudoNodeBinder()
        {
        }
        
        public String getName() {
            return "PseudoNodeBinder";
        }
        
        public void receivePolicyUpdate (String updateType,
                                         List policies) 
        {
            System.out.println("PseudoNodeBinder::receivePolicyUpdate");
            System.out.println("updateType = " + updateType);
            System.out.println(policies);           
        }
    }       
    private String _agentId;
        
} 
