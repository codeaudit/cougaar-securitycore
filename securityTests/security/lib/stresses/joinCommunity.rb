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
    @stressId="StressComty"
    @testManager = nil
    @attackAgent = nil
    @listenerId = nil
    @filter = "IDMEF\\([^)]+\\) Classification\\(org.cougaar.core.security.monitoring.MESSAGE_FAILURE\\)" +
              ".*AdditionalData\\(MESSAGE_FAILURE_REASON:Invalid Community Request,.*"
  end

  def getStressIds()
    return [@stressId]
  end

  def setupStress
    # find an attack agent
    @attackAgent = findAttackAgent(@run) # method in misc.rb
    saveAssertion(@stressId,
              "Found attack agent: #{@attackAgent.name}" )
    # determine community manager from communities
    searchForCommunityManager
    @listenerId = @run.comms.on_cougaar_event do |event|
      eventCall(event)
    end
  end
  
  def executeStress
    thread = Thread.fork {
      begin
	issueJoinRequest
	waitForMessageFailure
	processResults
      rescue => ex
	 saveAssertion(@stressId,
             "Unable to run test: #{ex}\n#{ex.backtrace.join("\n")}" )
      end
    }
  end

  def issueJoinRequest 
    # access the @attackAgent/joinCommunity?agent=@testAgent&community=@testCommunity&manager=@testManager
    #url = "http://#{@attackAgent.node.host.host_name}:#{@attackAgent.node.cougaar_port}/$#{@attackAgent.name}/joinCommunity" +
      "?agent=#{@testAgent}&community=#{@testCommunity}&manager=#{@testManager}"
    url = "#{@attackAgent.uri}/joinCommunity" +"?agent=#{@testAgent}&community=#{@testCommunity}&manager=#{@testManager}"
    begin
      logInfoMsg "Attempting to access #{url}" if $VerboseDebugging
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
      interval = 60
      sleep(interval)
      logInfoMsg "Sleeping #{interval} secs: Waiting for MESSAGE_FAILURE" if $VerboseDebugging
      count += 1
    end
    if count == 50
      logInfoMsg "Waiting for: MESSAGE_FAILURE TimedOut after #{interval*count} seconds"
      @timedOut = true
    end
  end
  
  def processResults
    if @timedOut == true && @msgFailureDetected == false
      saveResult(false, @stressId, "Timeout Didn't receive Invalid Community Request MESSAGE_FAILURE")
    elsif @msgFailureDetected == true
      saveResult(true, @stressId,"Detected Invalid Community Request MESSAGE_FAILURE")
    end
  end
  
  def searchForCommunityManager
    @run.society.communities.each do |community|
      community.each do |entity|
        if @attackAgent.name == entity.name
          community.each_attribute do |key, value|
            if key == 'CommunityManager'
              @testManager = value
              saveAssertion(@stressId, 
                "Found community manager for #{@attackAgent.name}: #{@testManager}")
              return 
            end
          end
        end # if @attackAgent.name == entity.name
      end
    end
    
  end
 
  #
  # called to process a CougaarEvent 
  #
  def eventCall(event)
    if event.cluster_identifier == @testManager &&
       event.component == 'IdmefEventPublisherPlugin' &&
       event.data =~ /#{@filter}/
       logInfoMsg "Detected Invalid Community Request MESSAGE_FAILURE" if $VerboseDebugging
       @msgFailureDetected = true       
       # remove the event listener
       @run.comms.remove_on_cougaar_event(@listenerId)
    end
  end
end
