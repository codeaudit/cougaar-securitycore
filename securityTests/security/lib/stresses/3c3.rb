require 'security/lib/certRevocation'
require 'security/lib/misc'
require 'security/lib/message_util'
require 'security/lib/rules'

class Security3c3 < SecurityStressFramework

   def initialize(run)
      super(run)
      @useIdmef = true
      @expired_node = nil
      @expired_agent_node = nil
      @expired_agent = nil
      @ssl_receiver_nodes = {}
      @ssl_initiator_nodes = {}
   end

   def preTransformSociety
      @certRevocation = CertRevocation.new
      @expired_node = @certRevocation.selectNode

      @expired_agent_node = @certRevocation.selectNode
      @certRevocation.installExpirationPlugin(@expired_node)
      @certRevocation.installExpirationPlugin(@expired_agent_node)

   end

   def postLoadSociety

      installSendMessageServlet
     
   end

   def postStartJabberCommunications
#      printDotsOnCougaarEvents
     on_cougaar_event do |event|
       if event.event_type == 'STATUS' && event.component == 'IdmefEventPublisherPlugin' && event.data =~ /MESSAGE_FAILURE/
         if event.data =~ /@expired_agent/
         puts "event: #{event.cluster_identifier}, #{event.component}, #{event.data}"
         end
         
       end

       # SSL expired Idmef message

       # message expired Idmef message
       msgPattern = /CertificateExpired([^)]*)/m
       if event.event_type == 'STATUS' && event.data =~ /Expired/
#         puts "event: #{event.cluster_identifier}, #{event.component}, #{event.data.to_s}"

         name = event.data.scan(msgPattern)
         raise "wrong revocation message found #{event.data}" unless name != []
          
         agent_name = name[0].to_s.split('(')[1]
         if agent_name == @expired_node.name
        
           if event.data =~ /ServerTrustManager/
#             summary "Confirmed SSL failure on expired certificate for node #{agent_name} as initiator."
             @ssl_receiver_nodes[event.cluster_identifier] = @expired_node.name
           elsif event.data =~ /ClientTrustManager/
#             summary "Confirmed SSL failure on expired certificate for node #{agent_name} as receiver."
             @ssl_initiator_nodes[event.cluster_identifier] = @expired_node.name
           end
         end

       end 
     end
   end

#   def postConditionalStartSociety
      # Give the agents time to retrieve their certificates
      # user admin may not be started yet
#      sleep 5.minutes 
   def postConditionalGLSConnection

      @caDomains = CaDomains.instance
      @caDomains.ensureExpectedEntities

      @certRevocation.setNodeExpiration(@expired_node, "1 s")

      @expired_agent = @certRevocation.selectAgentFromNode(@expired_agent_node)
      agent = run.society.agents[@expired_agent]
      @certRevocation.setAgentExpiration(agent, "1 s")


   Thread.fork {
      sleep 2.minutes

      @dest_agent = @certRevocation.selectAgent
      agent1 = run.society.agents[@expired_agent]
      agent2 = run.society.agents[@dest_agent]

      summary "The following nodes received SSL connection request from expired node:"
      summary "#{@ssl_receiver_nodes.keys.to_s}"

      result = false unless @ssl_receiver_nodes.keys.size != 0
      saveResult(result, "3c3", "SSL initiatored by node with expired certificate")

      summary "The following nodes initiated SSL connection request to expired node:"
      summary "#{@ssl_initiator_nodes.keys.to_s}"
      result = false unless @ssl_initiator_nodes.keys.size != 0
      saveResult(result, "3c4", "SSL received by node with expired certificate")

      testMessage(agent1, agent2) 

      sleep 2.minutes

#      exit 0      
      }
   end

   def testMessage(agent1, agent2)
    if (@useIdmef)
      testMessageIdmef(agent1.name, agent2.name,
                       '3c22', "Send message with expired cert IDMEF",
                       [ true, false, false, false ],
                       agent1.node.agent.name)
      testMessageIdmef(agent2.name, agent1.name,
                       '3c22', "Receive message with expired cert IDMEF", 
                       [ true, false, false, false ],
                       agent1.node.agent.name)
    end
    testMessageFailure(agent1.name, agent2.name, 
                       '3c10', "Send message with expired cert", 
                       [ true, false, false, false ])
    testMessageFailure(agent2.name, agent1.name, 
                       '3b10', "Receive message with expired cert", 
                       [ true, false, false, false ])
   end

   def printSummary
   end



end


