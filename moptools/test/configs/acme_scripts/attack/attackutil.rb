
    module Util
      MESSAGE_EVENTS = [ "Sent", "Received", "Responded", "ResponseReceived" ]

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
      def findAgents(component) 
#        print "Finding agents with component = #{component}\n"
        agents = Array.new
        getRun.society.each_agent(true) do |agent|
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
      def findAgentNames(component) 
        agents = findAgents(component)
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
        getRun.society.each_agent(true) do |agent|
          if (agent.name == agentName)
            return agent 
          end
        end
        return nil
      end # findAgent

      def getEnclave(agent)
        if (agent.kind_of? String)
          agent = getAgent(agentName)
        end
#	logInfoMsg("Agent #{agent.name} is on Node #{agent.node.name} on Host #{agent.node.host.name} with enclave #{agent.node.host.get_facet('enclave')}")
	agent.node.host.get_facet('enclave')
      end

      def getTestResultFile()
        filename = "#{$CIP}/workspace/test/attack_results.log"
        mkdirs(File.dirname(filename))
        File.new(filename,"a")
      end

      def modifyPolicy(enclave, header, text)
        # find the manager for the given community
        managers = findAgents("safe.policyManager.PolicyAdminServletComponent")
        manager = nil
        port    = nil
        host    = nil
        managers.each { |agent|
#          puts("looking at agent #{agent.name} which has enclave #{Util.getEnclave(agent)} comparing against enclave #{enclave}")
          if (Util.getEnclave(agent) == enclave)
            manager = agent.name
            port = agent.node.cougaar_port
            host = agent.node.host.name
            break;
          end
        }
        
        if manager == nil
          raise "There is no security manager for enclave '#{enclave}'"
        end
        
        # we've found the manager, now create the temporary policy file
	file = File.open("/tmp/modPolicy", "w")
	file.print(header)
	lines = File.readlines("#{$CIP}/configs/security/DamlBootPolicyList");
	file.puts(lines.join)
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
        
        results = `java #{defs.join} -classpath #{classpath.join(':')} org.cougaar.core.security.policy.builder.Main commit --dm --auth george george #{host} #{port} #{manager} /tmp/modPolicy`
#        puts "java #{defs.join} -classpath #{classpath.join(':')} org.cougaar.core.security.policy.builder.Main commit --dm --auth george george #{host} #{port} #{manager} /tmp/modPolicy"
	logInfoMsg results
      end # modifyPolicy

      def sendRelayMessage(source, target, &block)
#        puts "sending relay message from #{source} to #{target}"
        url = getUrl(source)
#        puts "the url = #{url}/message/send?xml=true&address=#{target}"
        result,url = Cougaar::Communications::HTTP.get("#{url}/message/send?xml=true&address=#{target}")
        raise "Error sending message from #{source} to #{target}" unless result
#        puts "sent relay message: #{result}"
        uid = nil
        result.scan("<uid>([^<]+)</uid>") { |match|
          uid = match[0]
        }
        if uid == nil
          raise "Could not extract UID from response when sending " +
            "message from #{source} to #{target}"
        end
#        puts "starting event watcher..."
        listener_num = getRun.comms.on_cougaar_event do |event|
          event.data.scan(/MessageTransport\((.*)\) UID\(#{uid}\) Source\(.*\) Target\(.*\)/) { |match|
            if (match[0] == "ResponseReceived")
              getRun.comms.remove_on_cougaar_event(listener_num)
            end
            yield(match[0])
          }
        end
#        puts "listener number = #{listener_num}"
        listener_num
      end # sendRelayMessage

      def relayMessageTest1(source, target, 
                           attackNum, attackName, 
                           maxWait = 5.minutes)
        relayMessageTest(source, Target, attackNum, attackName,
                         attackNum, attackName, [ true, true, true, true ],
                         nil, maxWait)
      end

      def relayMessageTest(source, target, 
                           attackNum, attackName, 
                           idmefNum, idmefName,
                           responsesExpected, 
                           stoppingAgent,
                           maxWait = 1.minutes)
#	puts "started relayMessageTest"
        responses = {}
        expected = {}
        responseArr = []
#	puts "in relayMessageTest"
        MESSAGE_EVENTS.each_index { |index|
          responses[MESSAGE_EVENTS[index]] = false
          expected[MESSAGE_EVENTS[index]] = responsesExpected
        }
#	puts "done setting expected values"
        idmefSrc = source
        idmefTgt = target
        if (expected["Received"])
          idmefSrc = target
          idmefTgt = source
        end
        shouldStop = true
        if (stoppingAgent == nil)
          shouldStop = false
          stoppingAgent = "[-0-9a-zA-Z_]+"
        end

#	puts "about to create idmef watcher"
        idmefWatcher = 
          IdmefWatcher.new(idmefNum, idmefName, shouldStop,
                           "IDMEF\\(#{stoppingAgent}\\) Classification\\(org.cougaar.core.security.monitoring.MESSAGE_FAILURE\\) Source\\(#{idmefSrc}/\\d+\\) Target\\(#{idmefTgt}/\\d+\\)")
        idmefWatcher.start

#	puts "started idmefWatcher"        
        listener = sendRelayMessage(source, target) { |result|
          responses[result] = true
          responseArr << result
        }
	puts "Sent relay message: #{listener}"
#        Thread.fork {
	puts "sleeping...."
        sleep(maxWait)
	puts "done sleeping"
        idmefWatcher.stop
        if (!responses["ResponseReceived"])
          getRun.comms.remove_on_cougaar_event(listener)
        end

	puts ("stopped...")
        saveResult(responses == expected,
                   attackNum, attackName + "\t" +
                   source + "\t" + target + "\t" + 
                   responseArr.join("\t"))
	puts("saved result")
#        }
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

      def getUrl(agent)
        agentName = nil
        if (agent.kind_of? String)
          agentName = agent
        else
          agentName = agent.name
        end
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
        result, url = Cougaar::Communications::HTTP.get("#{nameServer.uri}/$#{agentName}/list")
        raise "Could not reach name server" unless result
        # now hunt through the results for the agent and return the result
        url = url.to_s
        url[0..url.length - 6]
      end # getUrl

      def saveResult(pass, testnum, test)
        success = "SUCCESS"
        if !pass
          success = "FAILED"
        end
        file = getTestResultFile()
        file.print(success + "\t" + testnum + "\t" + test + "\n");
        file.close();
      end

      module_function :mkdirs, :mkfile, 
        :findAgents, :findAgentNames,
        :has_component?,
        :getAgent, :getEnclave,
        :saveResult, :modifyPolicy,
        :sendRelayMessage, :agentExists,
	:relayMessageTest,
        :getTestResultFile, :getUrl

      class IdmefWatcher 
        def initialize(attackNum, attackName, expected, idmefText)
          @attackNum = attackNum
          @attackName = attackName
          @expected = expected
          @idmefText = idmefText
          @idmefFound = false
          @listener = -1
        end

        def start
          @listener = getRun.comms.on_cougaar_event do |event|
            if event.data =~ /#{@idmefText}/
              # it gave an event
              @idmefFound = true
              stop
            end
          end
        end # start
        
        def stop
          if @listener != -1
            getRun.comms.remove_on_cougaar_event(@listener)
            @listener = -1
            Util.saveResult(@idmefFound == @expected, @attackNum, @attackName)
          end
        end
      end #IdmefWatcher
    end # module Util
