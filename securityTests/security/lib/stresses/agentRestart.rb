require 'security/lib/agent_mobility'
require 'security/lib/message_util'
require 'security/lib/misc'
require 'security/lib/common_security_rules'

require 'conf-full-1ad-ARUC1' unless $POLARIS

class InjectBlackboardCompromise < SecurityStressFramework
  def initialize(run)
    super(run)
  end

   def postLoadSociety
     installSendMessageServlet
   end

  def postConditionalNextOPlanStage
    logInfoMsg "Waiting 13 minutes for persitence snapshots to occur."
    sleep 13.minutes
    agent="2-BDE-1-AD"
    logInfoMsg "Comprimising #{agent}"
    mopValue = compromiseAgent(agent)
    logInfoMsg "Invoked servlet to compromise #{agent}"
    if mopValue == 100
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
  def compromiseAgent(agentname)
    @agentname=agentname
    mopValue = 0.0
    run.society.each_agent(true) do |agent|
      if agent.name==@agentname
        url = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/compromiseBlackboard"
        listurl  = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/list"
        params = []
        Cougaar::Communications::HTTP.post(url, params)
	logInfoMsg "Orginial location:#{listurl}"
	#wait unti agent restarted
	waitUntilAgentReady(20.minutes, agent)        
# wait for agent to rehydrate
        sleep 10.minutes        
        result,newurl = Cougaar::Communications::HTTP.get(listurl)
	logInfoMsg "Current location:#{newurl}"
# agent may be started on the same node, as long as it still has all the servlets
#       if newurl.to_s == taskurl.to_s
logInfoMsg "result: #{result}"
       if result =~ /completion/ && result =~ /tasks/
          mopValue = 100
       else
 	  mopValue = 0.0
       end 
       return mopValue
      end
    end 
  end

  
end

