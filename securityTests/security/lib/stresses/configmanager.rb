
class TestConfigurationManager < SecurityStressFramework
  def initialize(run)
    super(run)
  end

  def postConditionalNextOPlanStage
    agent="2-BDE-1-AD"
    moveToNode="MGMT-NODE"
    mopValue = testCM(agent)
    if mopValue==100
	success=true
    else
        success=false
    end if
    logInfoMsg "Invoked servlet to test configuration manager on #{agent} to node #{moveToNode}"
    description = "Test Configuration Manager, success=#{success}"
    logInfoMsg(description)
    saveResult(success,'N/A',description)
  end # postConditionalNextOPlanStage

  # Cougaar Actions to Trigger injection of blackboard compromise agent onto the blackboard
  #
  def testCM(agentname,movenode)
    @agentname=agentname
    @movenode = movenode 
    mopValue =0.0
    run.society.each_agent(true) do |agent|
    if agent.name==@agentname
      url = "#{agent.uri}/testCMServlet?node=#{movenode}"
      geturl = "#{agent.uri}/testCMServlet?getresult=true&testtype=M"

      Cougaar::Communications::HTTP.get(url)
      sleep 8.minutes
      result = Cougaar::Communications::HTTP.get(geturl)
      if result.to_s =~ /TRUE/
         mopValue=100    
      end 
   
    end
    return mopValue
  end


end

