require 'security/lib/certRevocation'
require 'security/lib/caDomain'
require 'security/lib/misc'
require 'security/lib/message_util'
require 'security/lib/rules'

class Security3c2 < SecurityStressFramework

   def initialize(run)
     super(run)
      @useIdmef = true
      @revoked_node = nil
      @revoked_agent = nil
      @ssl_initiator_nodes = {}
      @ssl_receiver_nodes = {}
      @msg_nodes = {}
      @src_agent = nil
      @dest_agent = nil
   end

   def getStressIds()
     return ["Stress3b9", "Stress3c9", "Stress3c21", "Stress5k103", "Stress5k104", "Stress3c2", "Stress3c5"]
   end

   def postLoadSociety
      @caDomains = CaDomains.instance
      @caDomains.ensureExpectedEntities

      # Send servlet now installed through a rule
      #installSendMessageServlet
   end

   def postStartJabberCommunications
      #printDotsOnCougaarEvents
     on_cougaar_event do |event|
#       puts "event: #{event.event_type}, #{event.cluster_identifier}, #{event.component}, #{event.data.to_s}"

       # message revoked Idmef message
       if event.event_type == 'STATUS' && event.component == 'IdmefEventPublisherPlugin' && event.data =~ /MESSAGE_FAILURE/
          #saveUnitTestResult('5k', "event: #{event.cluster_identifier}, #{event.component}, #{event.data}" )
         if event.data =~ /@revoked_agent/
           @msg_nodes[event.cluster_identifier] = @revoked_agent
         end
         
       end

       # SSL revoked Idmef message
       msgPattern = /CertificateRevoked([^)]*)/m
       if event.event_type == 'STATUS' && event.data =~ /Revoked/
          #saveUnitTestResult('5k', "event: #{event.cluster_identifier}, #{event.component}, #{event.data.to_s}" )

         name = event.data.scan(msgPattern)
         raise "wrong revocation message found #{event.data}" unless name != []
          
         agent_name = name[0].to_s.split('(')[1]
         if agent_name == @revoked_node.name
        
           if event.data =~ /ServerTrustManager/
#             summary "Confirmed SSL failure on revoked certificate for node #{agent_name} as initiator."
             @ssl_receiver_nodes[event.cluster_identifier] = @revoked_node.name
           elsif event.data =~ /ClientTrustManager/
#             summary "Confirmed SSL failure on revoked certificate for node #{agent_name} as receiver."
             @ssl_initiator_nodes[event.cluster_identifier] = @revoked_node.name
           end
         end

       end 

     end
   end

#   def postConditionalStartSociety
#      sleep 5.minutes unless $WasRunning

   def revokeNode(node)
      # Give the agents time to retrieve their certificates
      # user admin may not be started yet
      if (@certRevocation == nil)
        @certRevocation = CertRevocation.new
      end

      if (node == nil)
        saveResult("Stress5k103", "Error: could not find node to revoke")
      end
      result = @certRevocation.revokeNode(node)
       saveResult(result, "Stress5k103",
         "revoke a node through administrator: #{node.name}")
   end

   def revokeAgent(agent)
      # Give the agents time to retrieve their certificates
      # user admin may not be started yet
      if (@certRevocation == nil)
        @certRevocation = CertRevocation.new
      end

      result = @certRevocation.revokeAgent(agent)
      saveResult(result, "Stress5k104",
	 "revoke an agent through administrator: #{agent}")

      sleep(10.minutes)

      #@dest_agent = @certRevocation.selectAgent
      @dest_agent = getValidDestAgent()
      agent1 = @run.society.agents[agent]
      agent2 = @dest_agent
      saveUnitTestResult("Stress5k104", "Sending msg from #{agent1.name} to #{agent2.name}...")

      if (agent1 == nil) 
	raise "Unable to find source agent: #{agent}"
      end
      if (agent2 == nil) 
	raise "Unable to find destination agent"
      end
      testMessage(agent1, agent2)      

      summary "The following nodes received SSL connection request from revoked node:"
      summary "#{@ssl_receiver_nodes.keys.to_s}"
      result = false unless @ssl_receiver_nodes.keys.size != 0
      saveResult(result, "Stress3c2", "SSL initiated by node with revoked certificate.")

      summary "The following nodes initiated SSL connection request to revoked node:"
      summary "#{@ssl_initiator_nodes.keys.to_s}"
      result = false unless @ssl_initiator_nodes.keys.size != 0
      saveResult(result, "Stress3c5", "SSL received by node with revoked certificate.")
      #sleep(2.minutes)

   end

   def getValidDestAgent
     agentName = nil
     run.society.each_agent(true) do |agent|
       if !(agent.has_facet? "AgentAttacker")
	 agentName = agent
	 break
       end
     end
     return agentName
   end

   def getAttackAgent
     agentName = nil
     run.society.each_agent(true) do |agent|
       if agent.has_facet? "AgentAttacker"
	 agentName = agent
	 break
       end
     end
     return agentName
   end

   def getAttackNode
     nodeName = nil
     run.society.each_node do |node|
       if node.has_facet? "NodeAttacker"
	 nodeName = node
	 break
       end
     end
     return nodeName
   end

   def revokeAgentAndNode
     Thread.fork {
       begin
	 @revoked_agent = getAttackAgent()
	 @revoked_node = getAttackNode()
	 revokeAgent(@revoked_agent.name)
	 revokeNode(@revoked_node)
       rescue => ex
	 saveUnitTestResult('Stress3c2', "Unable to run test: #{ex}\n#{ex.backtrace.join("\n")}" )
       end
     }
   end

   def postConditionalGLSConnection
     Thread.fork {
       @revoked_node = @certRevocation.selectNode
       revokeNode(@revoked_node)

       @revoked_agent = @certRevocation.selectAgent
       revokeAgent(@revoked_agent)
     }
   end

   def testMessage(agent1, agent2)
    if (@useIdmef)
      testMessageIdmef(agent1.name, agent2.name,
        'Stress3c21',
	"Send message with expired cert IDMEF.",
        [ true, false, false, false ],
        agent1.node.agent.name)
      testMessageIdmef(agent2.name, agent1.name,
        'Stress3c21',
	"Receive message with expired cert IDMEF.", 
        [ true, false, false, false ],
        agent1.node.agent.name)
    end
    testMessageFailure(agent1.name, agent2.name, 
            'Stress3c9', "Send message with expired cert.", 
             [ true, false, false, false ])
    testMessageFailure(agent2.name, agent1.name, 
            'Stress3b9', "Receive message with expired cert.", 
            [ true, false, false, false ])
   end

   def printSummary
   end

end
