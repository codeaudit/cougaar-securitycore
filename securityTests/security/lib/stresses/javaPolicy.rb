
class Stress5f < SecurityStressFramework

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
    run.society.each_agent(true) do |agent|
      goodurl = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/AuthorizedResourceServlet"
      result = Cougaar::Communications::HTTP.get(goodurl)
      if result.to_s =~ /TRUE/
        @numberOfSuccess = @numberOfSuccess + 1
      else
        logWarningMsg "Unexpected response: #{result} at #{goodurl}"
      end
    end
    result = 100 * (@numberOfSuccess.to_f / @numberOfAgents.to_f)
    # Give two decimal precision
    if result.finite?
      result = (result * 100).round.to_f / 100
    end
    return mop
  end

  def invokeUnauthorizedServletsOnEveryAgent
    @numberOfSuccess = 0
    @numberOfAgents = 0
    result = 0.0
    run.society.each_agent(true) do |agent|
      badurl = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/UnAuthorizedResourceServlet"
      result = Cougaar::Communications::HTTP.get(badurl)
      if result.to_s =~ /TRUE/
        @numberOfSuccess = @numberOfSuccess + 1
      else
        logWarningMsg "Unexpected response: #{result} at #{badurl}"
      end
    end
    result = 100 * (@numberOfSuccess.to_f / @numberOfAgents.to_f)
    # Give two decimal precision
    if result.finite?
      result = (result * 100).round.to_f / 100
    end
    return mop
  end
e
  end

end # Stress5f

