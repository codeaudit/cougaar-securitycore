require 'framework/jar_util'

if ! defined? CIP
  CIP = ENV['CIP']
end

def waitForUserManager(agent, path="/userManagerReady", path2=nil)
  agent = run.society.agents[agent]

  nameServers = run.society.name_servers
  result = nil
  while (result == nil)
    nameServers.each { |nameServer|
      begin
        puts "talking to #{nameServer.uri}/agents?suffix=." if $COUGAAR_DEBUG
        result, url = Cougaar::Communications::HTTP.get("#{nameServer.uri}/agents?suffix=.", 30.seconds)
        if result =~ />#{agent.name}</
          # agent is ready
        else
          sleep 3.seconds
          result = nil
        end
      rescue Timeout::Error => e
        puts "Exception! #{e.message}"
        puts e.backtrace.join("\n")
        sleep 3.seconds
      rescue => e
        puts "Exception! #{e.message}"
        puts e.backtrace.join("\n")
        sleep 3.seconds
      end
      break if (result != nil)
    }
  end

  agentURL = agent.uri
  url = agentURL
  #             puts "url = #{url}"
  re = %r"http://#{agent.node.host.name}:([0-9]*)"
  #             puts "re = #{re}"
  match = re.match(url.to_s)
  #             puts "match done! #{match[1]}"
  if match != nil && match.size > 0 && match[1] != nil
    port = match[1].to_i
    #               puts "port = #{port}"
    if agent.node.cougaar_port != port
      agent.node.override_parameter("-Dorg.cougaar.lib.web.http.port", "#{port}")
    end
  end

  url = agent.node.agent.uri + path
  while (true)
    begin
      puts "Connecting to #{url}" if $COUGAAR_DEBUG
      result, url2 = Cougaar::Communications::HTTP.get(url)
      puts url2 if $COUGAAR_DEBUG
      puts result if $COUGAAR_DEBUG
      re1 = %r"<user>(.*)</user>"
      re2 = %r"<domain>(.*)</domain>"
      userMatch = re1.match(result)
      domainMatch = re2.match(result)
      if (userMatch != nil && domainMatch != nil &&
          userMatch[1] != "" && domainMatch[1] != "")
        # found it!
        return domainMatch
      end
      sleep 3.seconds
    rescue => e
      puts "Exception! #{e.message}"
      puts e.backtrace.join("\n")
      sleep 3.seconds
    end
  end
  if (path2 != nil)
    pokeURL = agentURL + path2
    result = nil
    while (result == nil)
      result, url2 = Cougaar::Communications::HTTP.get(pokeURL)
      if (result == nil || result =~ /HTTP Status 401/)
        result = nil
        sleep 10.seconds
      end
    end
  end
end # waitForUserManager

def getPolicyManager(enclave)
  manager = nil
  port    = nil
  host    = nil
  run.society.each_agent_with_component("safe.policyManager.PolicyAdminServletComponent") { |agent|
#    puts("looking at agent #{agent.name} which has enclave #{agent.enclave} comparing against enclave #{enclave}")
    if (agent.enclave == enclave)
      url = agent.uri
      re = %r"http://([^:]*):([^/]*)/\$([^/]*)"
      match = re.match(url)
      manager = agent.name
      port = match[2].to_i
      host = match[1]
      break;
    end
  }

  if manager == nil
    raise "There is no security manager for enclave '#{enclave}'"
  end
  [host, port, manager]
end

def getPolicyFile(enclave)
  filename = File.join(CIP,"workspace","policy","#{enclave}")
  Dir.mkdirs(File.dirname(filename));
  filename
end

def commitPolicy(host, port, manager, args, filename)
  # now commit the new policy
  policyUtil("#{args} --auth george george #{host} #{port} #{manager} #{filename}")
end

def policyUtil(args, javaArgs = nil, execDir = nil)
  # now commit the new policy
  classpath = getClasspath

  defs = [
    "-Dorg.cougaar.config.path=#{File.join(CIP,'configs','security')}",
    "-Dlog4j.configuration=#{File.join(CIP,'configs','common','loggingConfig.conf')}",
  ]

  if javaArgs != nil
    defs << javaArgs
  end

  cdCmd = ""
  if (execDir != nil)
    cdCmd = "cd #{execDir} && "
  end
  `#{cdCmd}java #{defs.join(" ")} -Xmx512m -classpath #{classpath.join(':')} org.cougaar.core.security.policy.builder.Main #{args}`
end

def deltaPolicy(enclave, text)
  if (!(defined? @policyLock))
    @policyLock = Mutex.new
  end
  host, port, manager = getPolicyManager(enclave)
  waitForUserManager(manager)
  @policyLock.synchronize {
    policyFile = getPolicyFile(enclave)
    begin
      File.stat(policyFile)
      fileExists = true
    rescue
      fileExists = false
    end
    if !fileExists
      # load the boot policies -- we haven't done any delta yet
      bootPolicyFile = File.join(CIP, "configs", "security",
                                 "DamlBootPolicyList")
      result = commitPolicy(host, port, manager, "commit --dm", bootPolicyFile)
      logInfoMsg result
      sleep 30.seconds
    end
    # now create the delta file
    File.open(policyFile, "w") { |file|
      file.write(text)
    }
    result = commitPolicy(host, port, manager, "addpolicies --dm", policyFile)
    logInfoMsg result
  }
end

module Cougaar
   module Actions
      class CreateBootPolicies < Cougaar::Action
        DENIED = { "10" => ["11","12","13","21",
                            "22", "23"], 
                   "11" => ["12","13","21",
                            "22", "23"], 
                   "12" => ["13","21",
                            "22", "23"], 
                   "13" => ["21", "22", "23"], 
                   "21" => ["22", "23"], 
                   "22" => ["23"], 
                   "03" => ["20", "21", "22", "23"],
                   "20" => [ "04", 
                             "11","12","13","10"],
                   "04" => ["21", "22", "23"] } 

        def perform
          # read the original file
          lines = []
          run.society.each_agent(true) { |agent|
            lines << "Agent %\##{agent.name}\n"
          }
          clouds = {}
          run.society.each_host { |host|
            group = host.get_facet("group")
            if (group != nil) 
#              puts("group \##{group}: #{host.name}")
              if clouds[group] == nil
                clouds[group] = []
              end
              clouds[group] << host
            end
          }
          clouds.each_key { |key|
#            puts("looking at group #{key}");
            agents = []
            clouds[key].each { |host|
#              puts("looking at host #{host.name}");
              host.each_node { |node|
#                puts("looking at node #{node.name}");
                agents << "\"#{node.name}\""
                node.each_agent { |agent|
                  agents << "\"#{agent.name}\""
                }
              }
            }
#            puts("finished looking at all hosts and nodes");
            if !agents.empty?
              jval = '", "'
              line = "AgentGroup Cloud#{key} = { \"#{agents.join(jval)}\" }\n"
              lines << line
            end
          }

          newPolicies = []
          DENIED.each_pair { |cloud1, list|
            list.each { |cloud2|
              if (clouds.has_key?(cloud1) && clouds.has_key?(cloud2))
#              newPolicies << "Policy \"Deny#{cloud1}-to-#{cloud2}\" = [\n"
#              newPolicies << "  MessageAuthTemplate\n"
#              newPolicies << "  Deny messages from members of $AgentsInGroup\#Cloud#{cloud1} to members of $AgentsInGroup\#Cloud#{cloud2}\n"
#              newPolicies << "]\n"
#              newPolicies << "Policy \"Deny#{cloud2}-to-#{cloud1}\" = [\n"
#              newPolicies << "  MessageAuthTemplate\n"
#              newPolicies << "  Deny messages from members of $AgentsInGroup\#Cloud#{cloud2} to members of $AgentsInGroup\#Cloud#{cloud1}\n"
#              newPolicies << "]\n"

                newPolicies << "Policy \"Deny#{cloud1}-to-#{cloud2}\" = [\n"
                newPolicies <<  "GenericTemplate\n"
                newPolicies << "Priority = 3,\n"
                newPolicies << "$AgentsInGroup\#Cloud#{cloud1} is not authorized to perform\n"
                newPolicies << "$Action.daml#EncryptedCommunicationAction as long as\n"
                newPolicies << "the value of $Action.daml#hasDestination\n"
                newPolicies << "is a subset of the set $AgentsInGroup\#Cloud#{cloud2}\n"
                newPolicies << "and \n"
                newPolicies << "the value of $Ultralog/UltralogAction.daml#hasSubject\n"
                newPolicies << "is a subset of the complement of the set\n"
                newPolicies << "{ $Ultralog/Names/EntityInstances.daml#NoVerb }\n"
                newPolicies << "]\n"

                newPolicies << "Policy \"Deny#{cloud2}-to-#{cloud1}\" = [\n"
                newPolicies <<  "GenericTemplate\n"
                newPolicies << "Priority = 3,\n"
                newPolicies << "$AgentsInGroup\#Cloud#{cloud2} is not authorized to perform\n"
                newPolicies << "$Action.daml#EncryptedCommunicationAction as long as\n"
                newPolicies << "the value of $Action.daml#hasDestination\n"
                newPolicies << "is a subset of the set $AgentsInGroup\#Cloud#{cloud1}\n"
                newPolicies << "and \n"
                newPolicies << "the value of $Ultralog/UltralogAction.daml#hasSubject\n"
                newPolicies << "is a subset of the complement of the set\n"
                newPolicies << "{ $Ultralog/Names/EntityInstances.daml#NoVerb }\n"
                newPolicies << "]\n"
              end

            }
          }
          origFile = "#{CIP}/configs/security/DamlBootPolicyList.orig"
          prevFile = "#{CIP}/configs/security/DamlBootPolicyList"
          stopFile = "#{CIP}/configs/security/DamlBootPolicyList.completed"
#          puts("finished creating lines")
          origLines = File.readlines(origFile)
          policyLines = lines.concat(origLines).concat(newPolicies)
          prevLines = File.readlines(prevFile)
          rebuild = true
#          puts("new policy file = #{policyLines.join}")
          if policyLines == prevLines
            begin
              statCompleted = File.stat(stopFile)
              statPrev = File.stat(prevFile)
              if statCompleted.mtime > statPrev.mtime
                rebuild = false
              end
            rescue
            end
          end
          if rebuild
#            puts("rebuilding file")
            File.open(prevFile, "w") { |file|
              file.write(policyLines.join())
            }
#            puts("wrote to file... starting policyUtil #{Time.now}")
            output = policyUtil("--maxReasoningDepth 150 build --info #{prevFile}", nil, "#{CIP}/configs/security")
#            puts("done with policyUtil #{Time.now}")
#            puts(output)

            File.open(stopFile, "w") { }
            # add the files to the security config jar file
            configJar = "#{CIP}/configs/security/securityservices_config.jar"
            replaceFileInJar(configJar,
                             "#{CIP}/configs/security/DamlBootPolicyList")
            Dir["#{CIP}/configs/security/*.info"].each { |file|
              replaceFileInJar(configJar, file)
            }
            signJar(configJar, "#{CIP}/operator/signingCA_keystore", 
                    "privileged")
          end
        end
      end
   end
end
