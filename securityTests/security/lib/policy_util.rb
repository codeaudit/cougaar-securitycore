        
require 'ultralog/scripting'
require 'ultralog/services' 

require 'security/lib/jar_util'
require 'security/lib/misc'

$VerboseDebugging=false

if ! defined? CIP
  CIP = ENV['CIP']
end

if ! defined?(bootPoliciesIntialized)
  bootPolicies = []
end


class PolicyWaiter
  def initialize(run, node)
    @run = run
    @node = node
    @found = false
#    @run.info_message("Starting wait for policy commit at #{node}")
    @thread = 
      Thread.new() do
      begin 
        me = 
         @run.comms.on_cougaar_event do |event|
          if (event.data.include?("Guard on node " + node + 
                                  " received policy update")) then
            @found = true
            @run.comms.remove_on_cougaar_event(me)
          end
        end
      rescue => ex
        @run.info_message("exception in waiter thread = #{ex}")
        @run.info_message("#{ex.backtrace.join("\n")}")
      end
    end
  end

  def wait(timeout)
    t = 0
    while (!@found && timeout > t) do
      t += 1
      sleep 1
    end
    if (@found) then
#      @run.info_message("waited #{t} seconds for the policy")
      return true
    else
      Thread.kill(@thread)
#      @run.info_message("Policy did not propagate")
      return false
    end
  end      
end


def waitForUserManager(agent, path="/userManagerReady", path2=nil)
  agent = run.society.agents[agent]
  url = agent.node.agent.uri + path
  while (true)
    begin
      logInfoMsg "Connecting to #{url}" if $COUGAAR_DEBUG
      result, url2 = Cougaar::Communications::HTTP.get(url, 30.seconds)
      logInfoMsg url2 if $COUGAAR_DEBUG
      logInfoMsg result if $COUGAAR_DEBUG
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
      logInfoMsg "Exception! #{e.message}"
      logInfoMsg e.backtrace.join("\n")
      sleep 3.seconds
    rescue Timeout::Error => e
      logInfoMsg "Timeout connecting to #{url}" if $COUGAAR_DEBUG
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
    logInfoMsg("looking at agent #{agent.name} which has enclave #{agent.enclave} comparing against enclave #{enclave}") if $VerboseDebugging
    if (agent.enclave.downcase == enclave.downcase)
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
    logInfoMsg "Found manager for #{host}:#{port} #{manager}" if $VerboseDebugging
  end
  [host, port, manager]
end

def getPolicyDir()
  dir = "/tmp/bootPolicies-#{rand(1000000)}"
  logInfoMsg "temporary policy dir = #{dir}" if $VerboseDebugging
  Dir.mkdir(dir)
  `cd #{dir} && jar xf #{CIP}/configs/security/bootpolicies.jar`
  dir
end

def commitPolicy(host, port, manager, args, filename)
  # now commit the new policy
  policyUtil("#{args} --auth george george #{host} #{port} #{manager} #{filename}")
end

def policyUtil(args, javaArgs = nil, execDir = nil)
  # now commit the new policy
  classpath = getClasspath

  defs = [
    "-Xmx512m",
    "-Dorg.cougaar.config.path=#{File.join(CIP,'configs','security')}",
    "-Dorg.cougaar.util.ConfigFinder.ClassName=org.cougaar.core.security.config.jar.SecureConfigFinder",
    "-Dorg.cougaar.core.security.bootstrap.keystore=${COUGAAR_INSTALL_PATH}/configs/security/bootstrap_keystore",
    "-Dorg.cougaar.core.logging.log4j.appender.SECURITY.File=/tmp/policyUtil.log",
    "-Dlog4j.configuration=#{File.join(CIP, 'configs', 'security', 'cmdlineLoggingConfig.conf')}",
    "-Dorg.cougaar.core.logging.config.filename=${COUGAAR_INSTALL_PATH}/configs/security/cmdlineLoggingConfig.conf"
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
  puts "will try to get policy lock" if $VerboseDebugging
  $policyLockLock.synchronize {
    puts "GOT policy lock" if $VerboseDebugging
    mutex = $policyLock[enclave]
    if mutex == nil
      mutex = Mutex.new
      $policyLock[enclave] = mutex
    end
  }
  mutex
end

def loadBootPolicies(enclave)
  host, port, manager = getPolicyManager(enclave)
  waitForUserManager(manager)
  mutex = getPolicyLock(enclave)
  mutex.synchronize {
    policyDir = getPolicyDir()
    puts "load the boot policies -- we haven't done any delta yet" if $VerboseDebugging
    pw = PolicyWaiter.new(run, run.society.agents[manager].node.name)
    bootPolicyFile = File.join(policyDir, "OwlBootPolicyList")
    result = commitPolicy(host, port, manager, "commit --dm", bootPolicyFile)
    if (! pw.wait(120)) then
      raise "Boot policies did not propagate for enclave #{enclave}"
    end
    logInfoMsg result if $VerboseDebugging
    `rm -rf #{policyDir}`
  }
end 

def deltaPolicy(enclave, text)
  host, port, manager = getPolicyManager(enclave)
  logInfoMsg "Got policy manager for #{enclave} host #{host} port #{port} manager #{manager}" if $VerboseDebugging
  if ! bootPoliciesInitialized.includes(enclave) then
    loadBootPolicies(enclave)
    bootPoliciesInitialized.push(enclave)
  end
  logInfoMsg " TRY TO GET LOCK TO POLICY FILE" if $VerboseDebugging
  mutex = getPolicyLock(enclave)
  logInfoMsg " GOT LOCK TO POLICY FILE" if $VerboseDebugging
  mutex.synchronize {
    policyFile = getPolicyFile(enclave)
    # now create the delta file
    File.open(policyFile, "w") { |file|
      file.write(text)
    }
    result = commitPolicy(host, port, manager, "addpolicies --dm", policyFile)
  }
  logInfoMsg result if $VerboseDebugging
end
