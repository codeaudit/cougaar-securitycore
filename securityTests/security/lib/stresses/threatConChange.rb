#
# This stress will test the ThreatConLevel change from HIGH back to LOW when login
# failures are introduced
#
class ThreatConChange < SecurityStressFramework

  def initialize
    @enteredHIGH = false
    @enteredLOW = false
    @threat_con_om = "org.cougaar.core.security.monitoring.THREATCON_LEVEL"
    @pdm = "unknown"
    @enclave = "Fwd"
    @attackAgent = nil
    @userDomain = nil
  end

  def preStartSociety
    # find an agent in the first enclave to use as an attack target
    searchForTarget
    # modify the society RateCalculatorPlugin's arguments
    modifyComponent
    # determine the policy domain manager <enclave>PolicyDomainManager
    run.comms.on_cougaar_event do |event|
      eventCall(event)
    end
  end

  def postSocietyQuiesced
    setUserDomain
    # perform the invalid logins
    performLoginFailures
    waitForHIGH
    waitForLOW
=begin
    # sleep for a max of 10 minutes or at least until the THREATCON_LEVEL
    # has gone back to the LOW state
    count = 0
    # wait for the THREATCON_LEVEL LOW event
    logInfoMsg "Waiting for: THREATCON_LEVEL LOW"
    while @enteredLOW == false && count < 50
      #logInfoMsg "waiting(#{count}) for threat con to go back to the LOW state"
      sleep(10) # sleep for 1 sec
      count += 1
    end
    if count == 50 && @enteredLOW == false
      logInfoMsg "Finished: ***** Timeout ***** didn't receive THREATCON_LEVEL LOW"
    end
=end
    # check results
    processResults
  end
  
  #
  # process results of the test to determine  whether or not THREATCON_LEVEL went to
  # HIGH and LOW
  #
  def processResults
    passed = false
    msg = nil
    if @enteredHIGH == true && @enteredLOW == true
      passed = true 
      msg = "THREATCON_LEVEL increased and decreased with respect to the number of login failures"
    elsif @enteredHIGH == true
      msg = "THREATCON_LEVEL increased but did not decrease after login failures decreased" 
    elsif @enteredLOW == true
      msg = "THREATCON_LEVEL decreased but did not increase after login failures increased"
    else
      msg = "THREATCON_LEVEL did not change as a result of an increase or decrease in login failures"
    end
    saveResult(passed, "3e1, 3e2", msg)
  end 
 
  #
  # called to process a CougaarEvent 
  #
  def eventCall(event)
    #logInfoMsg event
    if event.cluster_identifier == @pdm &&
       event.component == 'ThreatConLevelReporter' &&
       event.data =~ /OPERATING_MODE/
       #logInfoMsg "operating mode detected from #{@pdm}"
      event.data.scan(/OPERATING_MODE\((.+), (.+), (.+)\)/) { |match|
        operation = match[0]
        op_mode = match[1]
        om_value = match[2] 
        #logInfoMsg "operation: #{operation}"
        #logInfoMsg "op_mode:   #{op_mode}"
        #logInfoMsg "om_value:  #{om_value}"
        if operation == "change" &&
           op_mode == @threat_con_om 
           if om_value == "HIGH"
             @enteredHIGH = true
             #logInfoMsg "Received THREATCON_LEVEL HIGH event" 
           elsif om_value == "LOW"
             @enteredLOW = true
             #logInfoMsg "Received THREATCON_LEVEL LOW event" 
           end
        end
      } 
    end
  end
  
  #
  # Perform the login failures to trigger THREATCON_LEVEL change to HIGH
  #
  def performLoginFailures
    servlet = '/move'
    user = 'george'
    badPasswd = 'thisisabadpasswd'
    params = ['Basic', @attackAgent, user, badPasswd, servlet, 401]
    count = 0
    while count < 5
      @userDomain.accessServlet(params)
      count += 1
    end 
=begin   
    # wait for the THREATCON_LEVEL HIGH event
    logInfoMsg "Waiting for: THREATCON_LEVEL HIGH" 
    count = 0 
    while @enteredHIGH == false && count < 10
      sleep(10)
      count += 1
    end
    if count == 10 && @enteredHIGH == false
      logInfoMsg "Finished: ***** Timeout ***** didn't receive THREATCON_LEVEL HIGH"
    end
=end
  end

  # 
  # Modify the RateCalculatorPlugin for LOGIN_FAILURE_RATE to minimize the window for
  # the THREATCON_LEVEL to change from HIGH to LOW to about 5 mins.
  #
  def modifyComponent
    plugin = 'org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin'
    agent = run.society.agents["#{@enclave}EnclaveMnRManager"] 
    #logInfoMsg "agent: #{agent.name}"
    agent.remove_component(plugin)
    agent.add_component do |c|
      c.classname = plugin
      # 20 sec polling interval
      c.add_argument("20") 
      # 5 (60 * 5) min window for login failures
      c.add_argument("300")
      c.add_argument("org.cougaar.core.security.monitoring.LOGIN_FAILURE")
      c.add_argument("org.cougaar.core.security.monitoring.LOGIN_FAILURE_RATE")
    end
  end # modifyComponent

  #
  # Search for the first agent in a non-security node.
  # This method sets @pdm (policy domain manager), @enclave and @attackAgent
  #
  def searchForTarget
    run.society.each_node do |node|
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
        #logInfoMsg "found first non-security node: #{node.name}"
        # get the enclave for this node
        @enclave = node.host.get_facet(:enclave).capitalize
        #logInfoMsg "enclave: #{@enclave}"
        @pdm = "#{@enclave}PolicyDomainManager"
        #logInfoMsg "pdm: #{@pdm}"
        node.each_agent do |agent|
          # get the first agent from this node
          @attackAgent = agent
          logInfoMsg "Found attack agent: #{@attackAgent.name}"
          break 
        end 
        return
      end # if securityComp == false
    end # run.society.each_node
  end # searchForTarget

  #
  # Set @userDomain for accessing servlets
  #  
  def setUserDomain
    UserDomains.instance.ensureUserDomains
    @userDomain = @attackAgent.userDomain
    if @userDomain == nil
      @userDomain = run.society.agents["#{attackAgent.name}"].userDomain
    end
  end 

  def waitForLOW
    # sleep for a max of 500 secs or at least until the THREATCON_LEVEL
    # has gone back to the LOW state
    count = 0
    # wait for the THREATCON_LEVEL LOW event
    logInfoMsg "Waiting for: THREATCON_LEVEL LOW"
    while @enteredLOW == false && count < 50
      #logInfoMsg "waiting(#{count}) for threat con to go back to the LOW state"
      sleep(10) # sleep for 1 sec
      count += 1
    end
    if count == 50 && @enteredLOW == false
      logInfoMsg "Finished: ***** Timeout ***** didn't receive THREATCON_LEVEL LOW"
    elsif @enteredLOW == true
      logInfoMsg "Finished: received THREATCON_LEVEL LOW" 
    end
  end

  def waitForHIGH
    # wait for the THREATCON_LEVEL HIGH event
    logInfoMsg "Waiting for: THREATCON_LEVEL HIGH"
    count = 0
    while @enteredHIGH == false && count < 10
      sleep(10)
      count += 1
    end
    if count == 10 && @enteredHIGH == false
      logInfoMsg "Finished: ***** Timeout ***** didn't receive THREATCON_LEVEL HIGH"
    elsif @enteredHIGH == true
      logInfoMsg "Finished: received THREATCON_LEVEL HIGH" 
    end
  end

end
