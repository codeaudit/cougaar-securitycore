require 'thread'
require 'security/lib/misc'
require 'security/lib/policy_util'

class StressWebs < SecurityStressFramework
  def initialize(run)
    super(run)
  end

  def postLoadSociety
#    puts "=============================== editing policies"
    run.do_action "CreateBootPolicies"
  end
end # StressWebs

class Stress3a1 < SecurityStressFramework
  def initialize(run, useIdmef = true)
    super(run)
    @useIdmef = useIdmef
  end

  def preTransformSociety
    host = installAttackHost
    host.add_node("MESSAGE-ATTACK-NODE") { |node|
      node.override_parameter('-Dorg.cougaar.lib.web.http.port', '8830');
      node.add_agent("MessageAttacker") { |agent|
      }
    }
    @agent = run.society.agents["MessageAttacker"]
#    puts("Attack host = #{host.name}")
#    puts("Attack agent = #{@agent.name} on node #{@agent.node.name}")
  end # preTransformSociety

  def postLoadSociety
    installSendMessageServlet
  end

  def postConditionalNextOPlanStage
    # find the source and target
    agent1 = @agent
    enclave = agent1.enclave
    agent2 = nil
    # now choose an agent in a different enclave
    nameserver = nil
    run.society.each_enclave { |testEnc|
      if (enclave != testEnc)
        run.society.each_enclave_agent(testEnc) { |agent|
          facetok = true
          agent.node.each_facet("role") { |facet|
            if (facet["role"].downcase() == "nameserver")
              facetok = false
              nameserver = agent
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
    if agent2 == nil
      agent2 = nameserver
    end
    run.info_message "Blocking messages between #{agent1.name} and #{agent2.name}"
    deltaPolicy(enclave, <<DONE)
PolicyPrefix=%3a1/
Agent %\##{agent1.name}
Agent %\##{agent2.name}

AgentGroup Group#{agent1.name} = { \"#{agent1.name}\" }
AgentGroup Group#{agent2.name} = { \"#{agent2.name}\" }

Policy BlockSend = [
   MessageAuthTemplate
   Deny messages from members of $AgentsInGroup#Group#{agent1.name} to
   members of $AgentsInGroup#Group#{agent2.name}
]

Policy BlockReceive = [
   GenericTemplate
   Priority = 3,
   $AgentsInGroup#Group#{agent2.name} is not authorized to perform
   $Action.daml#EncryptedCommunicationAction  
   as long as
   the value of $Action.daml#hasDestination
   is a subset of the set $AgentsInGroup#Group#{agent1.name}
   and the value of $Ultralog/UltralogAction.daml#hasSubject
   is a subset of the set { $Ultralog/Names/EntityInstances.daml#NoVerb }
#   MessageAuthTemplate
#   Deny messages from members of $AgentsInGroup#Group#{agent2.name} to
#   members of $AgentsInGroup#Group#{agent1.name}
]

DONE
#    puts "Sleeping 5 minutes while the new policy distributes"
    sleep 3.minutes
#    puts "Done sleeping...."
      
    if (@useIdmef)
      testMessageIdmef(agent1.name, agent2.name,
                       '3a20', "Send unauthorized message IDMEF",
                       [ true, false, false, false ],
                       agent1.node.agent.name)
      testMessageIdmef(agent2.name, agent1.name,
                       '3b20', "Receive unauthorized message IDMEF", 
                       [ true, false, false, false ],
                       agent1.node.agent.name)
    end
    testMessageFailure(agent1.name, agent2.name, 
                       '3a1', "Send unauthorized message", 
                       [ true, false, false, false ])
    testMessageFailure(agent2.name, agent1.name, 
                       '3b1', "Receive unauthorized message", 
                       [ true, false, false, false ])
    printSummary
    sleep 10.minutes if $WasRunning
  end # postConditionalNextOplanStage
end # Stress3a1

class Stress3a1mop < Stress3a1
  def initialize(run)
    super(run, false)
  end
end # Stress3a1mop
