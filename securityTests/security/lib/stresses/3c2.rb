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
    if (@certRevocation == nil)
      @certRevocation = CertRevocation.new
    end

    on_cougaar_event do |event|
      begin
        # puts "event: #{event.event_type}, #{event.cluster_identifier}, #{event.component}, #{event.data.to_s}"

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
              # summary "Confirmed SSL failure on revoked certificate for node #{agent_name} as initiator."
              @ssl_receiver_nodes[event.cluster_identifier] = @revoked_node.name
            elsif event.data =~ /ClientTrustManager/
              # summary "Confirmed SSL failure on revoked certificate for node #{agent_name} as receiver."
              @ssl_initiator_nodes[event.cluster_identifier] = @revoked_node.name
            end
          end # if agent_name
        end # if event.event_type
      rescue => ex
        logInfoMsg "Exception while processing event: #{event.to_s} - #{ex}\n #{ex.backtrace.join('\n')}"
      end
    end # on_cougaar_events
  end

  #   def postConditionalStartSociety
  #      sleep 5.minutes unless $WasRunning

  def revokeNode(node)
    # Give the agents time to retrieve their certificates
    # user admin may not be started yet

    if (node == nil)
      saveResult("false","Stress5k103", "Error: could not find node to revoke")
    end
    result = @certRevocation.revokeNode(node)
    saveResult(result, "Stress5k103",
               "revoke a node through administrator: #{node.name}")

    sleep(3.minutes)

    summary "The following nodes received SSL connection request from revoked node: #{@ssl_receiver_nodes.keys.join(" ")}"
    result = false unless @ssl_receiver_nodes.keys.size != 0
    saveResult(result, "Stress3c2", "SSL initiated by node with revoked certificate.")

    summary "The following nodes initiated SSL connection request to revoked node: #{@ssl_initiator_nodes.keys.join(" ")}"
    result = false unless @ssl_initiator_nodes.keys.size != 0
    saveResult(result, "Stress3c5", "SSL received by node with revoked certificate.")
  end

  def revokeAgent(agent)
    if (agent == nil) 
      raise "Unable to revoke nil agent"
    end

    # Prevent CRL to reach revoked agent.
    # That way, the revoked agent will succeed sending a message out,
    # and we can test that the receiver is blocking the message.
    uri = nil
    if agent.instance_of? Cougaar::Model::Agent
      uri = agent.node.agent.uri
    elsif agent.instance_of? Cougaar::Model::Node
      uri = agent.uri
    else
      raise "Unexpected type: #{agent.type}"
    end

    uriEnqueue = "#{uri}/crlMessageBinderServlet?crlEnqueueMsg=true"
    logInfoMsg "Blocking CRL at #{uriEnqueue}"
    result, url = Cougaar::Communications::HTTP.get(uriEnqueue)
    if !(result =~ /Success/)
      saveAssertion("Stress5k104", "Unable to block CRL msg at #{agent.name}\nURL: #{uriEnqueue}\n#{result}")
    end

    # Now, revoke the agent.
    result = @certRevocation.revokeAgent(agent)
    saveResult(result, "Stress5k104",
               "revoke an agent through administrator: #{agent.name}")

    #@dest_agent = @certRevocation.selectAgent
    @dest_agent = getValidDestAgent()
    agent2 = @dest_agent
    if (agent2 == nil) 
      raise "Unable to find destination agent"
    end

    # Sleep a little bit until the receiver receives the CRL
    sleep(5.minutes)

    saveAssertion("Stress5k104",
                  "Sending msg from #{agent.name} to #{agent2.name}... Sender does not have CRL")
    testMessage(agent, agent2, "Sender does not have CRL")      

    # Now, re-enable CRL to reach the revoked agent.
    uriDequeue = "#{uri}/crlMessageBinderServlet?crlEnqueueMsg=false"
    logInfoMsg "Reenabling CRL at #{uriDequeue}"
    result, url = Cougaar::Communications::HTTP.get(uriDequeue)
    if !(result =~ /Success/)
      saveAssertion("Stress5k104", "Unable to re-enable CRL msg at #{agent.name}\nURL: #{url}\n#{result}")
    end

    # Now that the sender has CRLs, try again.
    # The sender should not even send the relay message.
    saveAssertion("Stress5k104", "Sending msg from #{agent.name} to #{agent2.name}... Sender should have CRL")
    testMessage(agent, agent2, "Sender has CRL")

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
        revokeAgent(@revoked_agent)
        sleep(10.minutes)
        revokeNode(@revoked_node)

        sleep(5.minutes)
        # Request new certificates for the node and agent
        begin
          logInfoMsg "Requesting new cert for #{@revoked_node.agent.name}"
          @certRevocation.requestNewCertificate(@revoked_node, @revoked_node.agent, "10 d")
          saveAssertion('Stress3c2', "Requested new cert for #{@revoked_node.name}")
          logInfoMsg "Requesting new cert for #{@revoked_agent.name}"
          @certRevocation.requestNewCertificate(@revoked_node, @revoked_agent, "10 d")
          saveAssertion('Stress3c2', "Requested new cert for #{@revoked_agent.name}")
        rescue => ex2
          saveAssertion('Stress3c2',
                        "Unable to request new cert: #{ex2}\n#{ex2.backtrace.join("\n")}")
          
        end
      rescue => ex
        saveAssertion('Stress3c2', "Unable to run test: #{ex}\n#{ex.backtrace.join("\n")}" )
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

  def testMessage(agent1, agent2, comment)
    if (@useIdmef)
      testMessageIdmef(agent1.name, agent2.name,
                       'Stress3c21',
                       "Send message with revoked cert IDMEF - " + comment,
                       [ true, false, false, false ],
                       agent1.node.agent.name)
      testMessageIdmef(agent2.name, agent1.name,
                       'Stress3c21',
                       "Receive message with revoked cert IDMEF - " + comment, 
                       [ true, false, false, false ],
                       agent1.node.agent.name)
    end
    testMessageFailure(agent1.name, agent2.name, 
                       'Stress3c9', "Send message with revoked cert - " + comment, 
                       [ true, false, false, false ])
    testMessageFailure(agent2.name, agent1.name, 
                       'Stress3b9', "Receive message with revoked cert - " + comment, 
                       [ true, false, false, false ])
  end

end
