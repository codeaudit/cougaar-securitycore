
require 'security/lib/certRevocation'
require 'security/lib/misc'
require 'security/lib/caDomain'
require 'security/lib/message_util'
require 'security/lib/rules'

class Security3c4 < SecurityStressFramework

   def initialize(run)
      super(run)
      @testAgent = true

      @untrust_node = nil
      @newcanode = nil
      @untrust_agent = nil
      @newca = nil
      @rootcanode = nil

      @useIdmef = true
      @ssl_receiver_nodes = {}
      @ssl_initiator_nodes = {}
   end

  
   def preTransformSociety
      logInfoMsg "preTransformSociety"
      run.society.each_node do |node|
        node.each_facet do |facet|
          if facet['role']=='RootCertificateAuthority'
            @rootcanode = node
          end
        end
      end

      if @rootcanode == nil
        logErrorMsg "Error: could not find root CA node"
      end
      @certRevocation = CertRevocation.new
      @untrust_node = @certRevocation.selectNode
      @untrust_agent = @certRevocation.selectAgentFromNode(@untrust_node)
      @certRevocation.installExpirationPlugin(@untrust_node)

# introduce new CA into society

# add it to one node
      # change the node name
      @untrust_node.host.add_node('UNTRUST-CA-NODE') do |node|
#       node.add_facet('role' => 'RootCertificateAuthority')
       @newcanode = node
      end
      @newcanode.add_agent('UntrustCaManager')
puts "new node #{@newcanode.name}, #{@newcanode.host.name}"

   end

# there is no replace or remove argument function
   def postLoadSociety
      installSendMessageServlet
      rootca = nil
      if @rootcanode == nil
        logErrorMsg "Error: could not find root CA node"
      end
      @rootcanode.each_agent do |agent|
        rootca = agent
      end

       @newcanode.override_parameter('-Dorg.cougaar.lib.web.http.port', '8820')
       @newcanode.override_parameter('-Dorg.cougaar.lib.web.https.port', '9820')
   
      @newcanode.agent.remove_component('org.cougaar.core.security.crypto.AutoConfigPlugin')
      @newcanode.agent.add_component do |c|
        c.classname = "org.cougaar.core.security.certauthority.ConfigPlugin"
        c.priority = "HIGH"
        c.insertionpoint = "Node.AgentManager.Agent.SecurityComponent"
        c.add_argument("CN=Invalid_CA, OU=Root, O=DLA, L=MV, ST=CA, C=US, T=ca")
      end
      @newcanode.each_agent do |agent|
        @newca = agent
      end

      rootca.each_component do |c|
puts "component #{c.classname}"
          if c.classname =~ /CaServletComponent/
            ac = c.clone(@newca)
            @newca.add_component(ac)
          end
      end

puts "added new ca #{@newca.node.name}"
    
if @testAgent
# for testing agent just add additional argument
    components = @untrust_node.getComponentsMatching(/security.crypto.AutoConfigPlugin/)
    component = components[0]
    component.add_argument("#{@newca.node.host.name}:#{@newca.name}:#{@newca.node.cougaar_port}:#{@newca.node.secure_cougaar_port}")
else 
      @untrust_node.agent.remove_component('org.cougaar.core.security.crypto.AutoConfigPlugin')
      @untrust_node.agent.add_component do |c|
        c.classname = "org.cougaar.core.security.crypto.AutoConfigPlugin"
        c.priority = "HIGH"
        c.insertionpoint = "Node.AgentManager.Agent.SecurityComponent"
        c.add_argument("#{@newca.node.host.name}:#{@newca.name}:#{@newca.node.cougaar_port}:#{@newca.node.secure_cougaar_port}")

puts "added component #{c.arguments[0]} to #{@untrust_node.name}"
      end
end

   end


   def postStartJabberCommunications
      printDotsOnCougaarEvents
     on_cougaar_event do |event|

       # message untrusted Idmef message

       if event.event_type == 'STATUS' && event.data.to_s =~ /CertificateChainUntrusted/
       end 

       # SSL message
       msgPattern = /CertificateChainUntrusted([^)]*)/m
       if event.event_type == 'STATUS' && event.data =~ /Untrusted/
#         puts "event: #{event.cluster_identifier}, #{event.component}, #{event.data.to_s}"
         # dont record message related to the invalid CA
         if event.data =~ /UNTRUST-CA-NODE/
           next
         end

         name = event.data.scan(msgPattern)
         raise "wrong untrust message found #{event.data}" unless name != []
          
         agent_name = name[0].to_s.split('(')[1]
         if agent_name == @untrust_node.name
        
           if event.data =~ /ServerTrustManager/
#             summary "Confirmed SSL failure on untrusted certificate for node #{agent_name} as initiator."
             @ssl_receiver_nodes[event.cluster_identifier] = @untrust_node.name
           elsif event.data =~ /ClientTrustManager/
#             summary "Confirmed SSL failure on untrusted certificate for node #{agent_name} as receiver."
             @ssl_initiator_nodes[event.cluster_identifier] = @untrust_node.name
           end # else
         end # if agent_name
       end # if status
     end # event
   end

#   def postConditionalStartSociety
      # Give the agents time to retrieve their certificates
      # user admin may not be started yet
#      sleep 5.minutes
   def postConditionalGLSConnection

#if @testAgent
      @caDomains = CaDomains.instance
      @caDomains.ensureExpectedEntities

# kill the valid CA so that the agent cannot get certificate from that CA again
      agent = run.society.agents[@untrust_agent]
      caManager = agent.caDomains[0].signer
      canode = run.society.agents[caManager.name].node

#puts "killing #{canode.name}"
#      run.do_action "KillNodes", canode.name      

#    run.do_action "GenericAction" do |run|
#      @certRevocation.removeAgentIdentities(agent)

#      sleep 1.minutes
      @dest_agent = @certRevocation.selectAgent
      agent1 = run.society.agents[@untrust_agent]
      agent2 = run.society.agents[@dest_agent]
      testMessage(agent1, agent2) 
#    end
#else
      summary "The following nodes received SSL connection request from untrusted node:"
      summary "#{@ssl_receiver_nodes.keys.to_s}"
   
      result = false unless @ssl_receiver_nodes.keys.size != 0
      saveResult(result, "3c4", "SSL initiated by node with improperly signed certificate.");      

      summary "The following nodes initiated SSL connection request to untrusted node:"
      summary "#{@ssl_initiator_nodes.keys.to_s}"
      result = false unless @ssl_initiator_nodes.keys.size != 0
      saveResult(result, "3c7", "SSL received by node with improperly signed certificate.");      
#      exit 0      
#end

    end

   def testMessage(agent1, agent2)
    if (@useIdmef)
puts "test #{agent1.name} vs #{agent2.name}"

      testMessageIdmef(agent1.name, agent2.name,
                       '3c23', "Send message with untrusted cert IDMEF",
                       [ true, false, false, false ],
                       agent1.node.agent.name)
      testMessageIdmef(agent2.name, agent1.name,
                       '3c23', "Receive message with untrusted cert IDMEF", 
                       [ true, false, false, false ],
                       agent1.node.agent.name)
    end
    testMessageFailure(agent1.name, agent2.name, 
                       '3c11', "Send message with untrusted cert", 
                       [ true, false, false, false ])
    testMessageFailure(agent2.name, agent1.name, 
                       '3c11', "Receive message with untrusted cert", 
                       [ true, false, false, false ])
   end

   def printSummary
   end



end


