    module Util
      def has_component? (agent, comp)
        agent.each_component { |c|
          if (c.classname == comp)
            return true
          end
        }
        return false;
      end
  
      # finds and returns a list of agents containing the
      # given component
      def findAgents(society, component) 
#        print "Finding agents with component = #{component}\n"
        agents = Array.new
        society.each_agent(true) do |agent|
          if (has_component? agent, component) 
#              print "Agent #{agent.name} has component\n"
            agents.push(agent)
          else
#              print "Agent #{agent.name} does not have component\n"
          end
        end
        agents
      end #findAgents

      # finds and returns a list of agents containing the
      # given component
      def findAgentNames(society, component) 
        agents = findAgents(society, component)
        names = []
        agents.each() { |agent|
          names.push(agent.name)
        }
        names
      end #findAgentNames

      def mkdirs(dir) 
        head, tail = File.split(dir)
        if (head != "/")
          mkdirs(head)
        end

        begin
          stat = File.stat(dir)
        rescue
          Dir.mkdir(dir)
        end
      end

      def mkfile(filename, mode="w")
        mkdirs(File.dirname(filename))
        File.new(filename,mode)
      end

      def getAgent(agentName)
        society.each_node() do |node|
          if node.name == agentName
            return node.agent
          end
          node.each_agent() do |agent|
            if (agent.name == agentName)
              return agent 
            end
          end
        end
        return nil
      end # findAgent

      def getEnclave(agentName)
        agent = getAgent(agentName)
        return agent.node.host.get_facet("enclave")["enclave"]
      end

      def getTestResultFile()
        filename = "#{$CIP}/workspace/test/attack_results.log"
        mkdirs(File.dirname(filename))
        File.new(filename,"a")
      end

      def modifyPolicy(enclave, text)
        # find the manager for the given community
        managers = findAgents("safe.policyManager.PolicyAdminServletComponent")
        manager = nil
        port    = nil
        host    = nil
        managers.each { |agent|
          facet = agent.node.host.get_facet("enclave");
          if (facet != nil && facet["enclave"] == enclave)
            manager = agent
            port = agent.node.cougaar_port
            host = agent.node.host
            break;
          end
        }
        
        if manager == nil
          raise "There is no security manager for enclave '#{enclave}'"
        end
        
        # we've found the manager, now create the temporary policy file
        `cp #{$CIP}/configs/security/DamlBootPolicyList /tmp/modPolicy`
        
        file = File.open("/tmp/modPolicy", "a")
        file.print(text)
        file.close()
        
        # now commit the new policy
        classpath = [ 
          "#{$CIP}/lib/core.jar",
          "#{$CIP}/lib/kaos.jar",
          "#{$CIP}/lib/planning.jar",
          "#{$CIP}/sys/antlr.jar",
          "#{$CIP}/sys/dl.jar",
          "#{$CIP}/sys/iw.jar",
          "#{$CIP}/sys/jakarta-oro-2.0.5.jar",
          "#{$CIP}/sys/jdom.jar",
          "#{$CIP}/sys/jena.jar",
          "#{$CIP}/sys/jtp.jar",
          "#{$CIP}/sys/icu4j.jar",
          "#{$CIP}/sys/mail.jar",
          "#{$CIP}/sys/servlet.jar",
          "#{$CIP}/sys/xerces.jar",
          "#{$CIP}/lib/bootstrap.jar",
          "#{$CIP}/lib/securityservices.jar",
          "#{$CIP}/lib/util.jar",
          "#{$CIP}/sys/log4j.jar",
          "#{$CIP}/sys/tomcat_40.jar"
        ]
        defs = [
          "-Dorg.cougaar.config.path=#{$CIP}/configs/security",
          "-Dlog4j.configuration=#{$CIP}/configs/common/loggingConfig.conf",
        ]
        
        `java #{defs.join} -classpath #{classpath.join} org.cougaar.core.security.policy.builder.Main commit #{host} #{agent} #{port} /tmp/modPolicy`
      end # modifyPolicy

      def sendRelayMessage(source, target, &block)
        result = Cougaar::Communications::HTTP.get("#{society.agents[source].uri}/message/send?xml=true?address=#{target}")
        raise "Error sending message from #{source} to #{target}" unless result
        if result =~ %r"<uid>(.+)</uid>"
          uid = $1
        else
          raise "Could not extract UID from response when sending " +
            "message from #{source} to #{target}"
        end
        listener_num = getRun.comms.on_cougaar_event do |event|
          if event.data =~ %r"MessageTransport\((.*)\) UID\(#{uid}\) Source\(.*\) Target\(.*\)" &&
            if ($1 == "ResponseReceived")
              getRun.comms.remove_on_cougaar_event(listener_num)
            end
            yield(event)
          end
        end
        listener_num
      end # sendRelayMessage

      def relayMessageTest(source, target, attackType, responseExpected, 
                           maxWait = 5.minutes)
        responded = false
        responses = []
        listener = sendRelayMessage(source, target) { |event|
          event =~ /MessageTransport\(([^)])*\)/
          responses.push($1)
          if ($1 == "ResponseReceived")
            responded = true
          end
        }
        sleep(maxWait)
        success = "SUCCESS"
        if (responded != responseExpected) 
          success = "FAILED"
        end
        if (!responded)
          getRun.comms.remove_on_cougaar_event(listener)
        end

        file = getTestResultFile
        file.print(success + "\t" + attackType + "\t" + 
                   source + "\t" + target + "\t" + 
                   responses.join('\t') + "\n")
        file.close()
      end # relayMessageTest

      def agentExists(agent)
        begin
          # look for the name server
          nameServer = nil
          getRun.society.each_node do |node|
            node.each_facet("role") { |facet| 
              if facet["role"] == "NameServer"
                nameServer = node
                break
              end
            }
          end
#          print("name server = #{nameServer.uri}\n");
          result = Cougaar::Communications::HTTP.get("#{nameServer.uri}/agents?suffix=.")
          raise "Could not reach name server" unless result
          # now hunt through the results for the agent and return the result
          result =~ />\$#{agent}</
        rescue
          raise "Could not reach name server", $!
        end
      end # agentExists

      module_function :mkdirs, :mkfile, 
        :findAgents, :findAgentNames,
        :has_component?,
        :getAgent, :getEnclave,
        :getTestResultFile, :modifyPolicy,
        :sendRelayMessage, :agentExists
    
    end # module Util
