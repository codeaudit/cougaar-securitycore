require 'security/stresses/4a101'
#require 'security/lib/certRevocation'
#require 'security/lib/dataProtection'

#$ClearPersistenceAndLogs = false
$SocietyQuiescedTime = 2.hours

class Security4a102Experiment < Security4a101Experiment

  # Give the agents time to retrieve their certificates
  def postConditionalNextOPlanStage     #GLSConnection
    sleep 15.minutes  # give time for persistence snapshots to be taken
puts "run.count = #{run.count}"
    if run.count == 0
      # on the second run, don't clear persistence.
      $ClearPersistenceAndLogs = false
      $ClearLogs = true
puts "rehydrateAnAgent"
      rehydrateAnAgent
      sleep 10.minutes
      printSummary
    end
  end

  # when rehydrated may have passed next stage, the script does not seem to catch it
=begin
  def postConditionalStartSociety
Thread.fork {
    sleep 15.minutes  # give time for persistence snapshots to be taken
puts "run.count = #{run.count}"
    if run.count==1
      result = checkRehydration
      saveResult(result, "4a102", "rehydration of all persisted data")
      printSummary
    end
}
  end
=end

  def preConditionalGLSConnection
Thread.fork {
    sleep 15.minutes  # give time for persistence snapshots to be taken
puts "run.count = #{run.count}"
    if run.count==1
      result = checkRehydration
      saveResult(result, "4a102", "rehydration of all persisted data")
      printSummary
    end
}
  end

=begin
   def initialize
      super
   end

   def postLoadSociety
   end

   def postStartJabberCommunications
      printDotsOnCougaarEvents
      #on_cougaar_event do |event|
      #end
   end

this is in 4a101
  def checkRehydration
    result = true
    run.society.each_host do |host|
      host.each_node do |node|
        # list of agents
        entities = node.agents.collect {|agent| agent.name}
        entities << node.name
        puts "doing #{node.name}"

#        port = CertRevocation.new.getParameter(node, /http.port/, nil)
# request to get persistence status
#        url = "http://#{host.name}:#{port}/$#{node.name}/PersistenceVerificationServlet"
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
=end


#  def printSummary
#  end



end

