require 'security/lib/agent_mobility'
require 'security/lib/message_util'
require 'security/lib/misc'
require 'security/lib/common_security_rules'

require 'conf-full-1ad-ARUC1'
#require 'conf-full-1ad-ASARUC1'

$ChaseAgent = "123-MSB"
$ChaseAgent = "1-6-INFBN"
$ChaseNumKills = 3
$ChaseWaitTimeAfterRehydration = 0.minutes

class ChaseKill < SecurityStressFramework
  def initialize(run)
    super(run)
  end

  attr_accessor :killAgent, :numKills, :waitTimeBetween

  def initialize(killAgentName=$ChaseAgent, numKills=$ChaseNumKills, waitTimeAfterRehydration=$ChaseWaitTimeAfterRehydration)
    @killAgentName = killAgentName
    @numKills = numKills
    @waitTimeAfterRehydration = waitTimeAfterRehydration
  end

  def postLoadSociety
    installSendMessageServlet
=begin
    logInfoMsg "Adding BlackboardCompromisePlugin to each node agent"
    run.society.each_node_agent() do |agent|
      agent.add_component do |c|
        c.classname = 'org.cougaar.core.security.blackboard.BlackboardCompromisePlugin'
      end
    end

    logInfoMsg "Adding BlackboardCompromiseSensorPlugin to each agent"
    compromisePlugin = 'org.cougaar.core.security.monitoring.plugin.BlackboardCompromiseSensorPlugin'
    run.society.each_agent do |agent|
      agent.add_component do |c|
        c.classname = compromisePlugin
      end
    end
=end
=begin
    logInfoMsg "Adding CompromisBlackboardServlet to each agent"
    classname = 'org.cougaar.core.security.test.blackboard.CompromiseBlackboardServlet'
    url = '/compromiseBlackboard'
    run.society.each_agent do |agent|
      agent.add_component do |c|
        c.classname = classname
#        c.add_argument(compromisePlugin)
#        c.add_argument(url)
      end
    end
=end
  end

  def postConditionalNextOPlanStage
    logInfoMsg "Waiting 13 minutes for persistence snapshots to occur."
    sleep 13.minutes unless $WasRunning
    agent = @killAgentName
    mopTotal = 0
    logInfoMsg "Will kill agent #{agent} #{@numKills} times"
    Thread.fork() do
      @numKills.times do |n|
        begin
          logInfoMsg "Compromising #{agent} (#{n+1}th time)"
          mopValue = compromiseAgent(agent)
          logInfoMsg "Invoked servlet to compromise #{agent}"
          mopTotal += mopValue
          sleep waitTimeAfterRehydration
        rescue Exception
          logInfoMsg "Error in (chaseKill.rb).postConditionalNextOPlanStage thread"
          puts $!
        end
      end
    end

    if mopTotal == 100.0 * @numKills
      success = true
    else
      success = false
    end
    description = "Compromise Agent and Restart test result=#{success}"
    logInfoMsg description
    saveResult(success, "N/A",description)
  end # postConditionalNextOPlanStage

  # Cougaar Actions to Trigger injection of blackboard compromise agent onto the blackboard
  #
  def compromiseAgent(agentname, scope="Agent")
    agent = run.society.agents[agentname]
#    url = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/compromiseBlackboard?scope=#{scope}"
#    url = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/compromiseBlackboard"
#    taskurl  = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/tasks"

    url = agent.uri + "/compromiseBlackboard"
    taskurl = agent.uri + "/tasks"
puts "url=#{url}"
puts "taskurl=#{taskurl}"

    Cougaar::Communications::HTTP.get(url)
    #wait unti agent restarted
    sleep 2.minutes
    waitUntilAgentReady(40.minutes, agent)        
    logInfoMsg "Orginial location:#{taskurl}"
    result,newurl = Cougaar::Communications::HTTP.get(taskurl)
puts "newurl=#{newurl}"
    logInfoMsg "Current location:#{newurl}"
    if newurl.to_s == taskurl.to_s
      return 0.0
    else
      return 100.0
    end
  end

  
end
