require 'security/lib/certRevocation'

class Security5jExperiment < SecurityStressFramework

   def initialize(run)
      super(run)
      @revoked_agent = nil
      @agent_ca = nil
      @management = {}
      @notified_node = {}
      @providers = {}
      @certRevocation = nil

      @start_time = nil
      @last_time = nil
      @total_poll = 0
      @poll_nodes = {}

   end


   def getHtml(url)
      return Cougaar::Communications::HTTP.get(url)
   end

   def postLoadSociety
      @caDomains = CaDomains.instance
#      @caDomains.getNodeInfoFromSociety
      @caDomains.ensureExpectedEntities

      @certRevocation = CertRevocation.new
   end

   def postStartJabberCommunications
#      printDotsOnCougaarEvents
     on_cougaar_event do |event|
       if event.event_type == "STATUS" && event.cluster_identifier =~ /CrlManager/ 
# && event.component == /CrlAgentRegistrationPlugin/ 
         if event.data =~ /updateCRL/
#           if @management[event.cluster_identifier] != nil
#             puts "Revocation detected by manager #{event.cluster_identifier}"
             @management[event.cluster_identifier] = event.data
#           end
         end
       elsif event.event_type == "STATUS" && event.data =~ /newCRL/
# puts "event: #{event.event_type}, #{event.cluster_identifier}, #{event.component}, #{event.data.to_s}"
#         if event.data =~ /#{@revoked_agent}/         
           puts "Revocation received by node #{event.cluster_identifier}"
           @notified_node[event.cluster_identifier] = event.data
#         end
       elsif event.event_type == 'STATUS' && event.data =~ /crlPoller/
         if @start_time == nil
           @start_time = Time.now
         end
         @last_time = Time.now
         @total_poll += 1
         @poll_nodes[event.node] = event.node
#         puts "crlPoller #{@start_time}, #{@last_time}, #{@total_poll}, #{@poll_nodes}"
       end 
     end
   end

#   def postConditionalStartSociety
      # Give the agents time to retrieve their certificates
#      sleep 5.minutes 
   def postConditionalGLSConnection
      result = checkPolling
      saveResult(result, "5j105", "CRL polling done at a low frequency")
 
      checkCrlProvider
      @revoked_agent = @certRevocation.selectAgent
      @agent_ca = run.society.agents[@revoked_agent].caDomains[0].cadn

      @certRevocation.revokeAgent(@revoked_agent)

      # wait until all received information, then check results
      checkRevocationResults
    end

   def checkRevocationForReboot
      # kill one management node and rehydrate
      @revoked_agent = @certRevocation.selectAgent
      @agent_ca = run.society.agents[@revoked_agent].caDomains[0].cadn
      @certRevocation.revokeAgent(@revoked_agent)

      # find which management node the agent's node registered for crl info
      @management = {}
      @notified_node = {}

      node = run.society.agents[@revoked_agent].node
      
      
      run.do_action "KillNodes", node.name
      run.do_action "RestartNodes", node.name 
      run.do_action "GenericAction" do |run|
        checkRevocationResults
# exit 0
      end

    end

    def checkPolling
      sleep 10.minutes
      puts "check polling"
      nodes = run.society.each_node {|node| }
      if @start_time != nil
        diff_time = @last_time - @start_time
        summary "#{@total_poll} crl polls in #{diff_time.to_i} seconds for #{@poll_nodes.size} nodes"
        value = @total_poll/@poll_nodes.size
        value = (value * 3600)/diff_time.to_i
        summary "#{value} polls per node per hour"
    
        if value < 100
          return true
        end

      else
        summary "no polling recorded for #{nodes.size} nodes"
      end
      return false
    end

    def checkRevocationResults
      sleep 10.minutes

      puts "evaluating results from revocation"      

# find all managers registered for the ca
      registeredMgrs = []
      entities = []
      cnPattern = /CN=([^,]*)/im
      ca_cn = @agent_ca.scan(cnPattern)
      @providers.each do |manager, ca|
        nodeList = ca[ca_cn[0]]
#puts "nodeList #{nodeList}" 
        if nodeList != []
          registeredMgrs << manager
          entities += nodeList
        end
      end
#puts "mgrs #{registeredMgrs}, #{entities}"
      missing_managers = registeredMgrs - @management.keys

      result = false
      if missing_managers != []
        summary "The following CrlManagers failed to receive revocation notice:"
        summary "#{missing_managers}"
      else
        summary "Success! All managers received revocation notice."
        result = true
      end
      saveResult(result, "5j101", "Revocation notice received by all CrlProviders")

      # now check whether all nodes has received the revocation notice
      result = false

      missing_nodes = []
      entities.each do |entity|
#        puts "entity >#{entity.to_s}<"
        value = @notified_node[entity.to_s]
        if value == nil
          puts "missing #{entity}"
          missing_nodes << entity.to_s
        end
      end    
=begin
      @notified_node.keys.each do |key|
        puts "key >#{key}<"
      end 
      missing_nodes = entities - @notified_node.keys
=end
      if missing_nodes != []
        summary "The following nodes registered for #{@agent_ca} but fails to received CRL"
        summary "#{missing_nodes}"
      else
        summary "Success! All nodes registered for #{@agent_ca} has received CRL"
        result = true
      end
      saveResult(result, "5j103", "Revocation notice received by all nodes registered to CrlProviders")

      printSummary
   end

   def checkCrlProvider
     registrationPattern = /<TR><TD>\nCN=([^,]*).*<\/TD>\n<TD>\n<OL>(.*)<\/OL>/im
     nodePattern = /<LI>([^\n]*)\n/im
     # get all provider nodes

      @certRevocation.getManagement.each_value do |manager| 
        manager.each_agent do |agent|
          if agent.name =~ /CrlManager/
     # get which node registers to which CA
#puts "provider #{agent.name}"
            port = @certRevocation.getParameter(manager, /http.port/, nil)
#            url = "http://#{manager.host.name}:#{port}/$#{agent.name}/CRLRegistrationViewer"
            url = "http://#{manager.host.name}:#{agent.node.cougaar_port}/$#{agent.name}/CRLRegistrationViewer"
            response = getHtml(url)
#            scanResult = response.to_s.scan(registrationPattern)
            registeredDn = {}

            cn_name = nil
            nodeList = []
            response.to_s.each_line do |i|
#puts "i #{i.to_s}"
              cn = i.scan(/CN=([^,]*)/i)
              if cn != []
                cn_name = cn[0]
#puts "cn #{cn}"
              end
              
              node = i.scan(/<LI>([^\n]*)\n/i)
              if node != []
#puts "node #{node}"
                nodeList << node
              end
     
              if i =~ /<\/OL>/
                registeredDn[cn_name] = nodeList.clone
                nodeList = []
#puts "entry #{cn_name}, #{registeredDn[cn_name]}"
              end

              # get registered node list
#              nodeList = []
#              nodeList = i[1].to_s.scan(nodePattern).collect {|j| j.to_s}
#              registeredDn[i[0].to_s] = nodeList
#puts "entry #{i[0].to_s}, #{nodeList}"
            end # scanResult

            @providers[agent.name] = registeredDn
          end # if
        end # each_agent
      end # each_value
     
    end

   def printSummary
   end



end


