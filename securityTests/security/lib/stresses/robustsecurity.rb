require 'security/lib/agent_mobility'
require 'security/lib/message_util'
require 'security/lib/misc'
require 'security/lib/common_security_rules'

class StressDisturbAgent < SecurityStressFramework
  def initialize(run, testNum, testName,
                 waitTime = 10.minutes, delay = 0)
    super(run)
    @delay = delay
    @waitTime = waitTime
    @testNum = testNum
    @testName = testName
  end

  def postLoadSociety
    installSendMessageServlet
  end

  def getTargetHost(enclave)
#    puts "getTargetHost start"
    run.society.each_enclave_node(enclave) { |node|
      node.each_facet { |facet|
        if facet[:role] == $facetManagement
#          puts "getTargetHost done 1"
          return node.host
        end
      }
    }
#    puts "getTargetHost middle"
    run.society.each_enclave_node(enclave) { |node|
#      puts "getTargetHost done"
      return node.host
    }
#    puts "getTargetHost end"
  end
  
  def createNode(enclave, nodeName)
    host = getTargetHost(enclave)
    host.add_node(nodeName) {|node| @node = node}
  end

  def setAgent(enclave, suffix)
    @agent = run.society.agents["#{enclave.capitalize}#{suffix}"]
  end 
  
  def postConditionalNextOPlanStage
    if (@delay > 0)
      sleep(@delay)
    end
  end # postConditionalNextOPlanStage
end # StressDisturbAgent

=begin
class StressMoveAgent < StressDisturbAgent
  def initialize(run, testNum, testName,
                 agent, waitTime = 10.minutes, delay = 0)
    super(run, testNum, testName, agent, "#{agent.upcase}-NODE", waitTime, delay)
  end

  def postConditionalNextOPlanStage
    super
    # Now I'm ready to start moving agents
    beforeServlets = getServlets(@agent)
    success = moveAgent(@agent, @node)
    afterServlets = getServlets(@agent)
    servletSuccess = (beforeServlets == afterServlets)
    saveResult(success && servletSuccess, @testNum, @testName)
  end # postConditionalNextOPlanStage
end # StressMoveAgent

class StressRestartAgent < StressDisturbAgent
  def initialize(run, testNum, testName, agent, 
                 waitTime = 10.minutes, midDelay = 3.minutes, delay = 0)
    super(run, testNum, testName, agent, "#{agent.upcase}-NODE", waitTime, delay)
    @midDelay = midDelay
  end
  
  def postConditionalNextOPlanStage
    super
    
    # Now I'm ready to start moving agents
    beforeServlets = getServlets(@agent)
    success = moveAgent(@agent, @node, @waitTime)
    if (success)
      sleep(@midDelay)
      success = restartAgents(@node, @waitTime)
      if (success)
        afterServlets = getServlets(@agent)
        success = (beforeServlets == afterServlets)
      end
    end
    saveResult(success, @testNum, @testName)
  end # postConditionalNextOPlanStage
end # StressRestartAgent

class StressRebootAgent < StressDisturbAgent
  def initialize(run, testNum, testName, agent, 
                 waitTime = 10.minutes, midDelay = 3.minutes, delay = 0)
    super(run, testNum, testName, agent, "#{agent.upcase}-NODE", waitTime, delay)
    @midDelay = midDelay
  end
  
  def postConditionalNextOPlanStage
    super
    
    # Now I'm ready to start moving agents
    beforeServlets = getServlets(@agent)
    success = moveAgent(@agent, @node, @waitTime)
    if (success)
      sleep(@midDelay)
      success = rebootAgents(@node, @waitTime)
      if (success)
        afterServlets = getServlets(@agent)
        success = (beforeServlets == afterServlets)
      end
    end
    saveResult(success, @testNum, @testName)
  end # postConditionalNextOPlanStage
end # StressRebootAgent
=end

class StressMRRAgent < StressDisturbAgent
  def initialize(run, testNum, testName, agent,
                 waitTime = 10.minutes, midDelay = 3.minutes, delay = 0)
    super(run, testNum, testName, waitTime, delay)
    @midDelay = midDelay
    @agent = agent
  end

  def preTransformSociety
#    puts "Starting StressMRRAgent.preTransformSociety"
    match = /[A-Z][^A-Z]+/.match(@agent)
    @enclave = match[0].upcase()
    createNode(@enclave, "#{@agent.upcase()}-NODE")
#    puts "Finished StressMRRAgent.preTransformSociety"
  end

  def postLoadSociety
    super
#    puts "Starting postTransformSociety! #{@agent}"
    @agent = run.society.agents[@agent]
#    puts "Finished postTransformSociety! #{@agent.name}"
  end
  
  def postConditionalNextOPlanStage
    super
    
    # Now I'm ready to start moving agents
    beforeServlets = getServlets(@agent)
#    puts "In StressMRRAgent. Servlet list\n#{beforeServlets.join("\n")}"
    success = moveAgent(@agent, @node, @waitTime)
#    puts "In StressMRRAgent. Just moved the agent #{@agent.name}"
    if (success)
      sleep 30.seconds
      url = @node.agent.uri.sub(%r"(https?://[^/]*/).*", '\1')
      url = url + "$#{@agent.name}/list"
      afterServlets = getServletsFromURL(url, @agent)
#      puts "In StressMRRAgent. Servlet list\n#{afterServlets.join("\n")}"
      success = (afterServlets == beforeServlets) 
    end
    saveResult(success, @testNum[0], @testName[0])
    return nil if !success
    stressTest("move")

    return nil if @testNum[1] == nil

    sleep(@midDelay)
    rebootAgents(@node, @waitTime)
    success = waitUntilAgentReady(@waitTime, @agent, @node)
    if (success)
      afterServlets = getServlets(@agent)
      success = (beforeServlets == afterServlets)
    end
    saveResult(success, @testNum[1], @testName[1])

    return nil if !success

    stressTest("reboot")
    return nil if @testNum[2] == nil

    restartAgents(@node, @waitTime)
    success = waitUntilAgentReady(@waitTime, @agent)
    if (success)
      afterServlets = getServlets(@agent)
      success = (beforeServlets == afterServlets)
    end
    saveResult(success, @testNum[2], @testName[2])
    return nil if !success
    stressTest("restart")
  end # postConditionalNextOPlanStage

  def stressTest(testType)
  end #stressTest
end # StressMRRAgent

class Stress6a1 < StressMRRAgent
  STRESS_NUMS  = ['6a1', '6a2', '6a3']
  STRESS_NAMES = [
    "Move M&R Manager",
    "Reboot M&R Manager",
    "Restart M&R Manager"
  ]
  def initialize(run)
    super(run, STRESS_NUMS, STRESS_NAMES, "ConusEnclaveMnRManager",
          10.minutes, 6.minutes, 0.seconds)
  end
end # Stress6a1

class Stress6b1 < StressMRRAgent
  STRESS_NUMS  = ['6b1', '6b2', '6b3']
  STRESS_NAMES = [
    "Move CRL Manager",
    "Reboot CRL Manager",
    "Restart CRL Manager"
  ]
  def initialize(run)
    super(run, STRESS_NUMS, STRESS_NAMES, "ConusEnclaveCrlManager",
          10.minutes, 6.minutes, 0.minutes)
  end
end # Stress6b1

class Stress6c1 < StressDisturbAgent
  def initialize(run)
    super(run, "6c1", "Reboot CA", 10.minutes, 0.minutes)
  end

  def postConditionalNextOPlanStage
    super
    @agent = run.society.agents["ConusEnclaveCaManager"]
    @node = @agent.node
    
    # Now I'm ready to start moving agents
    beforeServlets = getServlets(@agent)
#    puts "rebooting agents"
    rebootAgents(@node, @waitTime)
    success = waitUntilAgentReady(@waitTime, @agent, @node)
#    puts "done rebooting agents"
    if (success)
#      puts "getting servlet"
      afterServlets = getServlets(@agent)
      success = (beforeServlets == afterServlets)
    end
    saveResult(success, @testNum, @testName)
  end # postConditionalNextOPlanStage

end # Stress6c1

class Stress6d1 < StressMRRAgent
  STRESS_NUMS  = ['6d1', '6d2', '6d3']
  STRESS_NAMES = [
    "Move Policy Manager",
    "Reboot Policy Manager",
    "Restart Policy Manager"
  ]
  def initialize(run)
    super(run, STRESS_NUMS, STRESS_NAMES, "ConusPolicyDomainManager",
          10.minutes, 6.minutes, 0.minutes)
  end
end # Stress6d1


class Stress6e1 < StressMRRAgent
  STRESS_NUMS  = ['6e1', '6e2', nil]
  STRESS_NAMES = [
    "Move Persistence Manager",
    "Reboot Persistence Manager",
    nil
  ]
  def initialize(run)
    super(run, STRESS_NUMS, STRESS_NAMES, "ConusEnclavePersistenceManager",
          10.minutes, 6.minutes, 0.minutes)
  end
end # Stress6e1

class Stress6f1 < StressMRRAgent
  STRESS_NUMS  = ['6f1', '6f2', '6f3']
  STRESS_NAMES = [
    "Move User Manager",
    "Reboot User Manager",
    "Restart User Manager"
  ]
  def initialize(run)
    super(run, STRESS_NUMS, STRESS_NAMES, "ConusUserAdminAgent",
          10.minutes, 6.minutes, 0.minutes)
  end
end # Stress6f1


class Stress6g1 < StressMRRAgent
  STRESS_NUMS  = ['6g1', '6g2', '6g3']
  STRESS_NAMES = [
    "Move Security Console Manager",
    "Reboot Security Console Manager",
    "Restart Security Console Manager"
  ]
  def initialize(run)
    super(run, STRESS_NUMS, STRESS_NAMES, "RearEnclaveConsoleManager",
          10.minutes, 6.minutes, 0.minutes)
  end
end # Stress6g1


