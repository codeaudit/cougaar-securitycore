require 'security/lib/certRevocation'
require 'security/lib/misc'
require 'security/lib/policy_util'

class Security3c8 < SecurityStressFramework
  def initialize(run)
    super(run)
    @useIdmef = true
  end

  def postLoadSociety
    installSendMessageServlet
  end

  def postConditionalGLSConnection
#  def postConditionalStartSociety
#    sleep 10.minutes

    # find the source and target
    @certRevocation = CertRevocation.new
    
    aagent = @certRevocation.selectAgent
    agent1 = run.society.agents[aagent]
    enclave = agent1.enclave
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

puts "do policy for #{enclave}, #{agent1.name}, #{agent2.name}"
    deltaPolicy(enclave, <<DONE)
PolicyPrefix=%3c8/
Agent %\##{agent1.name}
Agent %\##{agent2.name}

AgentGroup "Group#{agent1.name}" = { \"#{agent1.name}\" }
AgentGroup "Group#{agent2.name}" = { \"#{agent2.name}\" }

Delete DamlBootPolicyEncryptCommunication

Policy NonEncryptCommunication = [
  MessageEncryptionTemplate
  Require NSAApprovedProtection on all messages from members of
  the complement of
  $AgentsInGroup#Group#{agent1.name} to members of 
  the complement of
  $AgentsInGroup#Group#{agent2.name}
]

DONE
    
    puts "Sleeping 5 minutes while the new policy distributes"

    sleep 5.minutes
    puts "Done sleeping...."
      
    if (@useIdmef)
      testMessageIdmef(agent1.name, agent2.name,
                       '3c20', "Send unprotected message IDMEF",
                       [ true, false, false, false ],
                       agent2.node.agent.name)
    end
    testMessageFailure(agent1.name, agent2.name, 
                       '3c8', "Send unprotected message", 
                       [ true, false, false, false ])
    sleep 10.minutes if $WasRunning
  end # postConditionalGLSConnection
end # Stress3c8

