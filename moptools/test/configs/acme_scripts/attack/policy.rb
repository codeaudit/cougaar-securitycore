require "security/attack/attackutil"

class NoAttackMessage < SecurityStressFramework
  def initialize
    super
  end

  def postConditionalNextOPlanStage
    # find the source and target
    agent1 = Util.getAgent("MessageAttacker")
    enclave = Util.getEnclave(agent1)
    agent2 = nil
    # now choose an agent in a different enclave
    run.society.each_enclave { |testEnc|
      if (enclave != testEnc)
        run.society.each_enclave_agent(testEnc) { |agent|
          facetok = true
          agent.node.host.each_facet("service") { |facet|
            if (facet["service"] == "nameserver")
              facetok = false
            end
          }
          if (facetok)
            agent2 = agent
            break
          end
        }
        break if (agent2 != nil)
      end
    }
    Util.modifyPolicy(enclave, <<HEADER, <<DONE)
Agent %\##{agent1.name}
Agent %\##{agent2.name}
HEADER

Policy BlockReceiveCommunication = [
  GenericTemplate Priority = 3,
   %\##{agent2.name} is not authorized to perform
   $Action.daml\#EncryptedCommunicationAction as long as
   the value of $Action.daml\#hasDestination
   is a subset of the set { %\##{agent1.name} }
]

Policy BlockSendCommunication = [
  GenericTemplate Priority = 3,
   %\##{agent1.name} is not authorized to perform
   $Action.daml\#EncryptedCommunicationAction as long as
   the value of $Action.daml\#hasDestination
   is a subset of the set { %\##{agent2.name} }
]
DONE
    puts "Sleeping 5 minutes while the new policy distributes"
    sleep 1.minutes
    puts "Done sleeping...."
      
    Util.relayMessageTest(agent1.name, agent2.name, 
                          '3a1', "Send unauthorized message", 
                          '3a20', "Send unauthorized message IDMEF",
                          [ true, false, false, false ],
                          agent1.name)
    Util.relayMessageTest(agent2.name, agent1.name, 
                          '3b1', "Receive unauthorized message", 
                          '3b20', "Receive unauthorized message IDMEF", 
                          [ true, false, false, false ],
                          agent1.name)
  end # postConditionalNextOplanStage
end # NoAttackMessage

