require 'cougaar/communities'
#
# This stress will test the CommunityService access control default policy (Agents
# can only join/modify/remove their own community entry).  A call to the joinCommunity
# servlet that will attempt to join another agent to a community.  The community
# request should be denied, and an IDMEF MESSAGE_FAILURE event should be generated.
#
class JoinCommunity < SecurityStressFramework

  def initialize(run)
    super(run)
    @timedOut = false
    @msgFailureDetected = false
    # join community request on behave of this agent
    @testAgent = "MaliciousAgentXYZ"
    # join community request to this community 
    @testCommunity = "TestCommunityXYZ"
    @testManager = nil
    @attackAgent = nil
    @listenerId = nil
    @filter = "IDMEF\\([^)]+\\) Classification\\(org.cougaar.core.security.monitoring.MESSAGE_FAILURE\\)" +
              ".*AdditionalData\\(MESSAGE_FAILURE_REASON:Invalid Community Request,.*"
  end

  def getStressIds()
    return ["StressMaliciousJoinCommunity"]
  end

  def setupStress
    # find an attack agent
    searchForTarget
    # determine community manager from communities
    searchForCommunityManager
    @listenerId = @run.comms.on_cougaar_event do |event|
      eventCall(event)
    end
  end
  
  def executeStress
    thread = Thread.fork {
      issueJoinRequest
      waitForMessageFailure
      processResults
    }
  end

  def issueJoinRequest 
    # access the @attackAgent/joinCommunity?agent=@testAgent&community=@testCommunity&manager=@testManager
    url = "http://#{@attackAgent.node.host.host_name}:#{@attackAgent.node.cougaar_port}/$#{@attackAgent.name}/joinCommunity" +
          "?agent=#{@testAgent}&community=#{@testCommunity}&manager=#{@testManager}"
    begin
      logInfoMsg "Attempting to access #{url}"
      result = Cougaar::Communications::HTTP.get(url)
    rescue
      logInfoMsg "Unable to access #{url}"
    end
      #logInfoMsg "Response #{result}"
  end
  
  def waitForMessageFailure
    # wait for the message failure event
    logInfoMsg "Waiting for: MESSAGE_FAILURE"
    count = 0
    while @msgFailureDetected == false && count < 10
      sleep(10)
      logInfoMsg "Sleeping 10 secs: Waiting for MESSAGE_FAILURE"
      count += 1
    end
    if count == 10
      logInfoMsg "Waiting for: MESSAGE_FAILURE TimedOut"
      @timedOut = true
    end
  end
  
  def processResults
    if @timedOut == true && @msgFailureDetected == false
      saveResult(false, "StressMaliciousJoinCommunity", "Timeout Didn't receive Invalid Community Request MESSAGE_FAILURE")
    elsif @msgFailureDetected == true
      saveResult(true, "StressMaliciousJoinCommunity","Detected Invalid Community Request MESSAGE_FAILURE")
    end
  end
  
  def searchForCommunityManager
    @run.society.communities.each do |community|
      community.each do |entity|
        if @attackAgent.name == entity.name
          community.each_attribute do |key, value|
            if key == 'CommunityManager'
              @testManager = value
              logInfoMsg "Found community manager for #{@attackAgent.name}: #{@testManager}"
              return 
            end
          end
        end # if @attackAgent.name == entity.name
      end
    end
    
  end
  
   #
  # Search for the first agent in a non-security node.
  # This method sets @pdm (policy domain manager), @enclave and @attackAgent
  #
  def searchForTarget
    @run.society.each_node do |node|
      securityComp = false
      node.each_facet(:role) do |facet|
        if facet[:role] == $facetManagement ||
           facet[:role] == $facetSubManagement ||
           facet[:role] == $facetRootManagement ||
           facet[:role] == 'RootCertificateAuthority' ||
           facet[:role] == 'CertificateAuthority' ||
           facet[:role] == 'RedundantCertificateAuthority'
          securityComp = true
          break 
        end 
      end
      if securityComp == false
        logInfoMsg "Found first non-security node: #{node.name}"
        node.each_agent do |agent|
          # get the first agent from this node
          @attackAgent = agent
          logInfoMsg "Found attack agent: #{@attackAgent.name}"
          break 
        end 
        return
      end # if securityComp == false
    end # @run.society.each_node
  end # searchForTarget
 
  #
  # called to process a CougaarEvent 
  #
  def eventCall(event)
    if event.cluster_identifier == @testManager &&
       event.component == 'IdmefEventPublisherPlugin' &&
       event.data =~ /#{@filter}/
       logInfoMsg "Detected Invalid Community Request MESSAGE_FAILURE"
       @msgFailureDetected = true       
       # remove the event listener
       @run.comms.remove_on_cougaar_event(@listenerId)
    end
  end
end
