
class Stress1f1 < SecurityStressFramework
  def initialize
    @numberOfSuccess = 0
    @numberOfAgents = 0
  end
  def postConditionalNextOPlanStage
    mopValue = invokeServletsOnEveryAgent
    description="MOP 2.5 (audit): #{mopValue} - Success=#{@numberOfSuccess} / Total=#{@numberOfAgents}"
    if (mopValue == 100)
      success = true
    else
      success = false
    end
    logInfoMsg description
    saveResult(success, '1f1', description);
  end # postConditionalNextOPlanStage

  def invokeServletsOnEveryAgent
    @numberOfSuccess = 0
    @numberOfAgents = 0
    mop = 0.0
    run.society.each_agent(true) do |agent|
      @numberOfAgents = @numberOfAgents + 1
      url = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/testAuditServlet"
      result = Cougaar::Communications::HTTP.get(url)
      if result.to_s =~ /TRUE/
        @numberOfSuccess = @numberOfSuccess + 1
      else
        logWarningMsg "Unexpected response: #{result} at #{url}"
      end
      #logInfoMsg "Audit servlet result: #{result} for #{url}"
      #puts "Audit servlet result: #{result} for #{url}"
    end
    mop = 100 * (@numberOfSuccess.to_f / @numberOfAgents.to_f)
    # Give two decimal precision
    if mop.finite?
      mop = (mop * 100).round.to_f / 100
    end
    return mop
  end
end # Stress1f1

