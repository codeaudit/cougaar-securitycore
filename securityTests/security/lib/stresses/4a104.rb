
require 'security/lib/certRevocation'

class Security4a104Experiment < SecurityStressFramework
   def initialize
      super
      @moved_agents = []
   end



#   def postConditionalStartSociety

      # Give the agents time to retrieve their certificates
#      sleep 10.minutes 
   def postPublishNextStage
# 4A104, shut down one node and check recovery
      certRevocation = CertRevocation.new
      node = certRevocation.selectNode

        @moved_agents = node.agents.collect{|agent| agent.name}
        summary "agents on killed node #{node.name}"
        summary @moved_agents.as_string

      run.do_action "KillNodes", node.name

    Thread.fork {
      run.do_action "Sleep", 30.minutes

      run.do_action "GenericAction" do |run|
# 4A106
        checkPersistenceRecovery(node.name)
        printSummary
exit 0   # keep the society running so that we can re-run this.
      end
    }
  end



   def printSummary
   end


   def checkPersistenceRecovery(nodename)
puts "checkPersistenceRecovery #{nodename}"
     recReq = true
     recResp = true

# check if there is any recovery request
#     run.society.each_host do |host|
#       host.each_node do |node|

# need to check every node because dont know which node are agents moved to
        requestAgents = []
        recoverAgents = []
 
        run.society.each_node do |node|
         if node == nil
           next
         end

         port = CertRevocation.new.getParameter(node, /http.port/, nil)
# request to get persistence status
#         url = "http://#{host.name}:#{port}/$#{node.name}/PersistenceVerificationServlet"
         url = "#{node.url}/$#{node.name}/PersistenceVerificationServlet"
         response = getHtml(url)
# collect all agents that has rehydrated
      requestPattern = /<\/TD><TD>([^<]*)<\/TD><TD>RECOVERY_REQUEST/im
         requestAgents = requestAgents + response.body.scan(requestPattern).collect {|i| i.to_s}
      recoveryPattern = /<\/TD><TD>([^<]*)<\/TD><TD>KEY_RECOVERED/im
         recoverAgents = recoverAgents + response.body.scan(recoveryPattern).collect {|i| i.to_s}
       end

# compare with entities
 
           missing = @moved_agents - requestAgents
           if missing != []
             summary "#{nodename} missing agents for recovery request:"
             summary missing.as_string
             recReq = false
           else
             summary "#{nodename} all agents has requested recovery"
           end

# if so check recovery status
         if requestAgents != []
           missing = requestAgents - recoverAgents
           if missing != []
             summary "#{nodename} missing agents for recovery:"
             summary missing.as_string
             recResp = false
           else
             summary "#{nodename} all agents has recovered"
           end
         end
     saveResult(recReq, "4a104", "all agents moved by UC1 sent recovery request")
     saveResult(recResp, "4a106", "all agents moved by UC1 recovered")
     
   end 

end

