require "security/attack/attackutil"

class RequireSSL < SecurityStressFramework
#  def preConditionalGLSConnection
  def postConditionalNextOPlanStage
    Util.saveResult(!Util.agentExists('NO-SSL-ATTACK-NODE'),
                    '3c1', "Non-SSL Communication");
  end # postConditionalNextOPlanStage

  def postTransformSociety
    # remove SSL from the node that shouldn't have it

    sslRMI      = "org.cougaar.core.mts.SSLRMILinkProtocol"
    rmiProtocol = "org.cougaar.core.mts.RMILinkProtocol"
    insertion   = "Node.AgentManager.Agent.MessageTransport.Component"
    
    getRun.society.each_node do |node|
      # don't use SSL for RMI communication
      node.each_facet("attacker") do |facet|
        if (facet["attacker"] == "NonSSL")
          node.remove_component(sslRMI)
          
          # make sure that either RMI exists instead
          node.add_component do |component|
            component.classname = rmiProtocol
            component.insertionpoint = insertion
          end
          break # out of the facet loop
        end
      end
    end
  end # postTransformSociety
end # RequireSSL

# agent should successfully send a message
class Stress3a101 < SecurityStressFramework
  def intialize 
    @answered = false
    @saved = false
  end

  def postConditionalNextOPlanStage
    # find two random agents. They should be allowed to communicate
    # if they are not in the attack node
    agent1 = nil
    agent2 = nil
    society.each_agent { |agent|
      if (agent.node.get_facet["attacker"] == nil)
        if (agent1 == nil) 
          agent1 = agent
        else
          if (agent1.node != agent.node) 
            agent2 = agent
            break
          end
        end
      end
    }

    Util.relayMessageTest(agent1.name, agent2.name, 
                          '3ab101', "Send message successfully")
  end # postConditionalNextOPlanStage
end # Stress3a101

