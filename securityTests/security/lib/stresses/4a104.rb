
require 'security/lib/certRevocation'

class Security4a104Experiment < SecurityStressFramework
   def initialize(run)
      super(run)
   end



#   def postConditionalStartSociety

      # Give the agents time to retrieve their certificates
#      sleep 10.minutes 
   def postPublishNextStage
# 4A104, shut down one node and check recovery

      certRevocation = CertRevocation.new
      node = certRevocation.selectNode

        moved_agents = node.agents.collect{|agent| agent.name}
        summary "agents on killed node #{node.name}"
        summary moved_agents.as_string

      run.do_action "KillNodes", node.name

    Thread.fork {
      run.do_action "Sleep", 10.minutes

      run.do_action "GenericAction" do |run|
# 4A106
        checkPersistenceRecovery(node.name, moved_agents)
        printSummary
#exit 0   # keep the society running so that we can re-run this.
      end
    }
  end



   def printSummary
   end


   def checkPersistenceRecovery(nodename, moved_agents)
#puts "checkPersistenceRecovery #{nodename}"
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
         url = "#{node.uri}/#{node.name}/PersistenceVerificationServlet"
       begin
         response = getHtml(url)
       rescue => ex
         next
       end
# collect all agents that has rehydrated
      requestPattern = /<\/TD><TD>([^<]*)<\/TD><TD>RECOVERY_REQUEST/im
         requestAgents = requestAgents + response.body.scan(requestPattern).collect {|i| i.to_s}
      recoveryPattern = /<\/TD><TD>([^<]*)<\/TD><TD>KEY_RECOVERED/im
         recoverAgents = recoverAgents + response.body.scan(recoveryPattern).collect {|i| i.to_s}
       end

# compare with entities
 
           missing = moved_agents - requestAgents
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

class Security4b104Experiment < Security4a104Experiment

   def postPublishNextStage     
# 4b104, shut down CA and management node and check recovery
      certRevocation = CertRevocation.new

      enclaves = {}
# select an enclave
      run.society.each_node do |node|
        node.each_facet(:role) do |facet|
          if facet[:role] == 'CertificateAuthority' \
          or facet[:role] == 'AS-Management' \
          or facet[:role] == 'AR-Management'
          enclave = node.host.get_facet(:enclave)
          entry = enclaves[enclave]
          if entry == nil
            entry = {}
            enclaves[enclave] = entry
          end
          puts "adding #{node.name} for #{enclave}"
          entry[facet[:role]]= node
          end
        end
      end

# get its CA and management node
      index = rand(enclaves.keys.size)
      enclave = enclaves.keys[index]
          puts "selecting #{enclave}"
      kill_nodes = enclaves[enclave]

# kill CA, then management node, then AR manager node
      run.do_action "KillNodes", kill_nodes['CertificateAuthority'].name
      run.do_action "Sleep", 1.minutes

      mgmt_node = kill_nodes['AS-Management']
        moved_agents = mgmt_node.agents.collect{|agent| agent.name}
        summary "agents on killed node #{mgmt_node.name}"
        summary moved_agents.as_string

      run.do_action "KillNodes", mgmt_node.name
      run.do_action "Sleep", 1.minutes

      ar_node = kill_nodes['AR-Management']
        ar_agents = ar_node.agents.collect{|agent| agent.name}
        summary "agents on killed node #{ar_node.name}"
        summary ar_agents.as_string
      run.do_action "KillNodes", ar_node.name
      run.do_action "Sleep", 1.minutes

    Thread.fork {
      run.do_action "Sleep", 10.minutes

      run.do_action "GenericAction" do |run|
# 4b106
        checkPersistenceRecovery(mgmt_node.name, moved_agents)
        checkPersistenceRecovery(ar_node.name, ar_agents)
        printSummary
#exit 0   # keep the society running so that we can re-run this.
      end
    }

  end

end
