
require 'security/lib/certRevocation'
require 'security/lib/dataProtection'
require 'security/lib/agent_mobility'
require 'security/lib/rules'

class Security4a101Experiment < SecurityStressFramework
   def initialize(run)
      super(run)
      @certRevocation = nil
   end


   def postLoadSociety
     installSendMessageServlet
   end

   def postStartJabberCommunications
      printDotsOnCougaarEvents
      #on_cougaar_event do |event|
      #end
   end

      # Give the agents time to retrieve their certificates
   def postConditionalNextOPlanStage    #GLSConnection
     sleep 10.minutes   # give time for persistence snapshots to be taken
puts "rehydrateAnAgent"
     rehydrateAnAgent
     printSummary
   end

   def rehydrateAnAgent
      @certRevocation = CertRevocation.new
# 4A101
      puts "check persistence"
      result = checkPersistence
      dataProtection = DataProtection.new
      dataProtectionMop = dataProtection.checkDataEncrypted('cougaar')
      result = (dataProtectionMop >= 100)
      
      saveResult(result, "4a101", "protection of all persisted data") 
      orig_node = nil
      dest_node = nil
      move_agent = nil

# 4A103, move one agent through move servlet 
      orig_node = @certRevocation.selectNode
      dest_node = @certRevocation.selectNode
      while [nil, 'NCA'].member?(move_agent)
        move_agent = @certRevocation.selectAgentFromNode(orig_node)
      end
puts "move agent #{move_agent} from #{orig_node.name} to #{dest_node.name}"

      moveAgent(move_agent, dest_node.name, 20.minutes)
#      run.do_action "MoveAgent", move_agent, dest_node.name
      puts "agent #{move_agent} is back up"

#      run.do_action "Sleep", 2.minutes

#      run.do_action "GenericAction" do |run|
#        logInfoMsg "Waiting for agent to rehydrate"
#        waitForSingleAgentStart(20.minutes, move_agent)
        sleep 5.minutes

        checkAgentRehydration(move_agent, dest_node) 
#exit 0   # keep the society running so that we can re-run this.
      
#      end
   end

  def checkPersistence
    result = true

    run.society.each_host do |host|
      host.each_node do |node|
puts node.name
        # list of agents 
        entities = node.agents.collect {|agent| agent.name}
        entities << node.name
#        puts "doing #{node.name}"

        port = @certRevocation.getParameter(node, /http.port/, nil)
# request to get persistence status
#        url = "http://#{host.name}:#{port}/$#{node.name}/PersistenceVerificationServlet"
        url = "#{node.uri}/$#{node.name}/PersistenceVerificationServlet"
        puts "#{url.to_s}"
        response = getHtml(url)
#         puts "#{response.to_s}"
# collect all agents that has persisted
        agentPattern = /<\/TD><TD>([^<]*)<\/TD><TD>OUTPUT_COMPLETE/im
        agents = response.body.scan(agentPattern).collect {|i| i.to_s}
# compare with entities
        missing = entities - agents

        if missing != []
          summary "#{node.name} missing agents for persistence:"
          summary missing.as_string
          result = false
        else
          summary "#{node.name} all agents persisted"
        end
         
      end # each node
    end # each host
    return result
  end

  def checkRehydration
    result = true
    run.society.each_host do |host|
      host.each_node do |node|
        # list of agents
        entities = node.agents.collect {|agent| agent.name}
        entities << node.name
        puts "doing #{node.name}"

#         port = @certRevocation.getParameter(node, /http.port/, nil)
# request to get persistence status
#         url = "http://#{host.name}:#{port}/$#{node.name}/PersistenceVerificationServlet"
        url = "#{node.uri}/$#{node.name}/PersistenceVerificationServlet"
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
          result = false
        else
          summary "#{node.name} all agents rehydrated"
        end

      end # each node

    end # each host
    return result
  end

  def checkAgentRehydration(agent, node)
    puts "checking #{agent} rehydration on #{node.name}"
#         port = @certRevocation.getParameter(node, /http.port/, nil)
# request to get persistence status
#         url = "http://#{node.host.name}:#{port}/$#{node.name}/PersistenceVerificationServlet"
    url = "#{node.uri}/$#{node.name}/PersistenceVerificationServlet"
    response = getHtml(url)
puts response.body

# collect all agents that has persisted

#puts "received response #{response.to_s}"
    agentPattern = /<\/TD><TD>([^<]*)<\/TD><TD>OUTPUT_COMPLETE/im
    agents = response.body.scan(agentPattern).collect {|i| i.to_s}

# compare with entities
    result = false
    if agents == []
      summary "#{node.name} missing #{agent} for rehydration"
    else
      summary "Success! #{agent} rehydrated on #{node.name}"
      result = true
    end
    saveResult(result, "4a103", "moved agent rehydration")

  end 


#  def printSummary
#  end



end


