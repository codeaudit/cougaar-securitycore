require 'security/lib/jar_util'

if ! defined? CIP
  CIP = ENV['CIP']
end

def waitForUserManager(agent, path="/userManagerReady", path2=nil)
  agent = run.society.agents[agent]
  url = agent.node.agent.uri + path
  while (true)
    begin
      puts "Connecting to #{url}" if $COUGAAR_DEBUG
      result, url2 = Cougaar::Communications::HTTP.get(url, 30.seconds)
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
    rescue Timeout::Error => e
      puts "Timeout connecting to #{url}" if $COUGAAR_DEBUG
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
    #puts("looking at agent #{agent.name} which has enclave #{agent.enclave} comparing against enclave #{enclave}")
    if (agent.enclave == enclave)
      #url = agent.uri
      #re = %r"http://([^:]*):([^/]*)/\$([^/]*)"
      #match = re.match(url)
      manager = agent.name
      port = agent.node.cougaar_port
      host = agent.node.host.name
      #port = match[2].to_i
      #host = match[1]
      break;
    end
  }

  if manager == nil
    raise "There is no security manager for enclave '#{enclave}'"
  else
    logInfoMsg "Found manager for #{host}:#{port} #{manager}"
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
    "-Dlog4j.configuration=#{File.join(CIP, 'configs', 'security', 'cmdlineLoggingConfig.conf')}",
    "-Dorg.cougaar.core.logging.config.filename=#{File.join(CIP, 'configs', 'security', 'cmdlineLoggingConfig.conf')}",
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

$policyLockLock = Mutex.new
$policyLock = Hash.new

def getPolicyLock(enclave)
  mutex = nil
  #puts "will try to get policy lock"
  $policyLockLock.synchronize {
    #puts "GOT policy lock"
    mutex = $policyLock[enclave]
    if mutex == nil
      mutex = Mutex.new
      $policyLock[enclave] = mutex
    end
  }
  mutex
end

def bootPoliciesLoaded(enclave)
  host, port, manager = getPolicyManager(enclave)
  waitForUserManager(manager)
  mutex = getPolicyLock(enclave)
  mutex.synchronize {
    #puts "TRYING TO GET POLICY FILE FOR ENCLAVE #{enclave}"
    policyFile = getPolicyFile(enclave)
    begin
      File.stat(policyFile)
      fileExists = true
    rescue
      fileExists = false
    end
    #puts "boot policy file exists #{fileExists}"
    if !fileExists
      #puts "load the boot policies -- we haven't done any delta yet"
      bootPolicyFile = File.join(CIP, "configs", "security",
                                 "OwlBootPolicyList")
      result = commitPolicy(host, port, manager, "commit --dm", bootPolicyFile)
      #puts " result after commitPolicy #{result}"
#      logInfoMsg result
    end
    fileExists  
  }
end 

def deltaPolicy(enclave, text)
  host, port, manager = getPolicyManager(enclave)
  #puts "Got policy manager for #{enclave} host #{host} port #{port} manager #{manager}"
  bootPoliciesAlreadyLoaded = bootPoliciesLoaded(enclave)
  #puts " CHECKING IF bootPoliciesLoaded ALREADY LOADED FOR #{enclave}"
  if !bootPoliciesAlreadyLoaded
     #puts "first time so sleeping for 30 seconds"
    sleep 30.seconds
  else 
     #puts "second time so I don't need to sleep"
  end
  #puts " TRY TO GET LOCK TO POLICY FILE"
  mutex = getPolicyLock(enclave)
  # puts " GOT LOCK TO POLICY FILE"
  mutex.synchronize {
    
    policyFile = getPolicyFile(enclave)
    # now create the delta file
    File.open(policyFile, "w") { |file|
      file.write(text)
    }
    result = commitPolicy(host, port, manager, "addpolicies --dm", policyFile)
  }
#    logInfoMsg result
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
                newPolicies << "$Action.owl#EncryptedCommunicationAction as long as\n"
                newPolicies << "the value of $Action.owl#hasDestination\n"
                newPolicies << "is a subset of the set $AgentsInGroup\#Cloud#{cloud2}\n"
                newPolicies << "and \n"
                newPolicies << "the value of $Ultralog/UltralogAction.owl#hasSubject\n"
                newPolicies << "is a subset of the complement of the set\n"
                newPolicies << "{ $Ultralog/Names/EntityInstances.owl#NoVerb }\n"
                newPolicies << "]\n"

                newPolicies << "Policy \"Deny#{cloud2}-to-#{cloud1}\" = [\n"
                newPolicies <<  "GenericTemplate\n"
                newPolicies << "Priority = 3,\n"
                newPolicies << "$AgentsInGroup\#Cloud#{cloud2} is not authorized to perform\n"
                newPolicies << "$Action.owl#EncryptedCommunicationAction as long as\n"
                newPolicies << "the value of $Action.owl#hasDestination\n"
                newPolicies << "is a subset of the set $AgentsInGroup\#Cloud#{cloud1}\n"
                newPolicies << "and \n"
                newPolicies << "the value of $Ultralog/UltralogAction.owl#hasSubject\n"
                newPolicies << "is a subset of the complement of the set\n"
                newPolicies << "{ $Ultralog/Names/EntityInstances.owl#NoVerb }\n"
                newPolicies << "]\n"
              end

            }
          }
          origFile = "#{CIP}/configs/security/OwlBootPolicyList.orig"
          prevFile = "#{CIP}/configs/security/OwlBootPolicyList"
          stopFile = "#{CIP}/configs/security/OwlBootPolicyList.completed"
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
                             "#{CIP}/configs/security/OwlBootPolicyList")
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
