
require 'security/lib/certRevocation'

class Csi7a < SecurityStressFramework
   attr_accessor :revokedAgent
   attr_accessor :modifiedAgent

   def postStartJabberCommunications
      printDotsOnCougaarEvents
     on_cougaar_event do |event|
#       puts "event: #{event.cluster_identifier}, #{event.data}"
       if event.data =~ "DATA_FAILURE_REASON,No certificates"
         if event.cluster_identifier == revokedAgent
           puts "Detected rehydration failure event for revoked agent #{revokedAgent}"
         end
       elsif event.data =~ "DATA_FAILURE_REASON,Verify digest failure"
         if event.cluster_identifier == modifiedAgent
           puts "Detected rehydration failure event for agent #{modifiedAgent} with persistent data modified"
         end
       end
     end
   end

   def postConditionalStartSociety
      # Give the agents time to retrieve their certificates
      sleep 10.minutes unless $WasRunning
# 4A101
      puts "check persistence"
#      checkPersistence
#      dataProtection = DataProtection.new
#      dataProtection.checkDataEncrypted('cougaar')

      puts "check rehydration"
      run.do_action "StopSociety"

# 4A102     
      run.do_action "Sleep", 2.minutes
      run.do_action "StartSociety"

      run.do_action "Sleep", 2.minutes
      run.do_action "GenericAction" do |run|
        CaDomains.instance.ensureExpectedEntities
        checkRehydration


# 4A103, move one agent through move servlet 
          certRevocation = CertRevocation.new
          orig_node = certRevocation.selectNode
          dest_node = certRevocation.selectNode
          move_agent = certRevocation.selectAgentFromNode(orig_node)
          moveAgent(move_agent, dest_node)

          sleep 2.minutes
          checkAgentRehydration(move_agent, dest_node)
        printSummary
exit 0   # keep the society running so that we can re-run this.
        end

      end

   def moveAgent(move_agent, dest_node)
      run.do_action "MoveAgent", move_agent, dest_node.name
   end

   def checkPersistence
     run.society.each_host do |host|
       host.each_node do |node|
         # list of agents 
         entities = node.agents.collect {|agent| agent.name}
         entities << node.name
         puts "doing #{node.name}"

         port = getParameter(node, /http.port/, nil)
# request to get persistence status
         url = "http://#{host.name}:#{port}/$#{node.name}/PersistenceVerificationServlet"
         puts "#{url.to_s}"
         response = getHtml(url)
         puts "#{response.to_s}"
# collect all agents that has persisted
      agentPattern = /<\/TD><TD>([^<]*)<\/TD><TD>OUTPUT_COMPLETE/im
         agents = response.body.scan(agentPattern).collect {|i| i.to_s}
# compare with entities
	 missing = entities - agents

         if missing != []
           summary "#{node.name} missing agents for persistence:"
           summary missing.as_string
         else
           summary "#{node.name} all agents persisted"
         end
         
       end # each node
     end # each host
   end

   def checkRehydration
     run.society.each_host do |host|
       host.each_node do |node|
         # list of agents
         entities = node.agents.collect {|agent| agent.name}
         entities << node.name
         puts "doing #{node.name}"

         port = getParameter(node, /http.port/, nil)
# request to get persistence status
         url = "http://#{host.name}:#{port}/$#{node.name}/PersistenceVerificationServlet"
         puts "#{url.to_s}"
         response = getHtml(url)
         puts "#{response.to_s}"
# collect all agents that has persisted
      agentPattern = /<\/TD><TD>([^<]*)<\/TD><TD>INPUT_COMPLETE/im
         agents = response.body.scan(agentPattern).collect {|i| i.to_s}

# compare with entities
         missing = entities - agents

         if missing != []
           summary "#{node.name} missing agents for rehydration:"
           summary missing.as_string
         else
           summary "#{node.name} all agents rehydrated"
         end

       end # each node

     end # each host
   end

   def checkAgentRehydration(agent, node)
         puts "checking #{agent} rehydration on #{node.name}"
         entities << agent

         port = getParameter(node, /http.port/, nil)
# request to get persistence status
         url = "http://#{host.name}:#{port}/$#{node.name}/PersistenceVerificationServlet"
         response = getHtml(url)
# collect all agents that has persisted
      agentPattern = /<\/TD><TD>([^<]*)<\/TD><TD>INPUT_COMPLETE/im
         agents = response.body.scan(agentPattern).collect {|i| i.to_s}

# compare with entities
         missing = entities - agents

         if missing != []
           summary "#{node.name} missing agents for rehydration:"
           summary missing.as_string
         else
           summary "#{node.name} all agents rehydrated"
         end

       end 

      # get parameter from node given param name
      def getParameter(node, paramName, default)
        node.each_parameter do |p|
          (name, value) = p.to_s.split('=')
          return value if name =~ paramName
        end

        puts "No parameter found for #{paramName} on #{node.name}"
        return default
      end


   def printSummary
   end
end
