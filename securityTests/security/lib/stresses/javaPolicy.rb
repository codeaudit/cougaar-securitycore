require "security/lib/cougaarMods"

class Stress5f < SecurityStressFramework
  def initialize(run)
    @run = run
  end

  def postConditionalNextOPlanStage
    # ##################
    # Authorized servlet
    result = invokeAuthorizedServletsOnEveryAgent
    description="Java security policy (authorized resource) success Rate: #{result} - Success=#{@numberOfSuccess} / Total=#{@numberOfAgents}"
    if (result == 100)
      success = true
    else
      success = false
    end
    logInfoMsg description
    saveResult(success, '5f', description);

    # ####################
    # Unauthorized servlet
    result = invokeUnauthorizedServletsOnEveryAgent
    description="Java security policy (unauthorized resource) success Rate: #{result} - Success=#{@numberOfSuccess} / Total=#{@numberOfAgents}"
    if (result == 100)
      success = true
    else
      success = false
    end
    logInfoMsg description
    saveResult(success, '5f', description);

  end # postConditionalNextOPlanStage

  def invokeAuthorizedServletsOnEveryAgent
    @numberOfSuccess = 0
    @numberOfAgents = 0
    result = 0.0
    @run.society.each_agent(true) do |agent|
      @numberOfAgents += 1
      goodurl = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/AuthorizedResourceServlet"
      begin
        result = Cougaar::Communications::HTTP.get(goodurl)
      rescue
	puts "Unable to access #{goodurl}"
      end
      if result.to_s =~ /TRUE/
        @numberOfSuccess = @numberOfSuccess + 1
      else
	saveUnitTestResult('5f', "Unexpected response: #{result} at #{goodurl}" )
      end
    end
    result = 100 * (@numberOfSuccess.to_f / @numberOfAgents.to_f)
    # Give two decimal precision
    if result.finite?
      result = (result * 100).round.to_f / 100
    end
    return result
  end

  def invokeUnauthorizedServletsOnEveryAgent
    @numberOfSuccess = 0
    @numberOfAgents = 0
    result = 0.0
    @run.society.each_agent(true) do |agent|
      @numberOfAgents += 1
      badurl = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/UnAuthorizedResourceServlet"
      begin
        result = Cougaar::Communications::HTTP.get(badurl)
      rescue
	puts "Unable to access #{goodurl}"
      end
      if result.to_s =~ /TRUE/
        @numberOfSuccess = @numberOfSuccess + 1
      else
	saveUnitTestResult('5f', "Unexpected response: #{result} at #{badurl}")
      end
    end
    result = 100 * (@numberOfSuccess.to_f / @numberOfAgents.to_f)
    # Give two decimal precision
    if result.finite?
      result = (result * 100).round.to_f / 100
    end
    return result
  end
end # Stress5f

