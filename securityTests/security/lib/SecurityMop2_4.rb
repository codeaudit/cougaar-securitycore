require 'security/lib/AbstractSecurityMop'
require 'security/lib/SecurityMop2_5'
require 'security/lib/rules'
#require 'security/lib/userDomain'
#require 'security/lib/policy_util'
#require 'security/lib/misc.rb'

$MinimumUnauthorizedServletAttempts = 2

noScore = 100

class  SecurityMop2_4 < AbstractSecurityMop
  include Singleton
  attr_accessor :numAccessAttempts,       :numAccessesCorrect,          :logins
  attr_accessor :numActionsLogged,        :numLoggableActions,          :actions
  attr_accessor :numPoliciesLogged,       :numLoggablePolicies,         :policies
  attr_accessor :numtotalAccessAttempts,  :numtotalAccessAttemptCorrect, :totalactions
  attr_accessor :calcDone, :performDone
  attr_accessor :maxWaitTime, :numTimeouts
  
  def initialize()
    # super(run)
    reset
    removePemCertificates
    @name = "2-4"
    @descript = "Percentage of user actions that were available for invocation counter to authorization policy"
    @maxWaitTime = 10.minutes
  end

  def getStressIds()
    return ["SecurityMop2.4","1A1-1A20","1A2-1A21","1A4-1A23","1A5-1A24","1A51-1A241","1A6-1A25","1A7-1A26","1A8-1A27","1A9-1A28","1A10-1A29"]
  end

  def removePemCertificates
    begin
      `rm -f pems/*.pem` unless $WasRunning
    rescue Exception
      logInfoMsg "Unable to remove pem files"
    end
  end

  def reset
    # this method will be called once per run (if run.count=3, it will be called three times).
    @numAccessAttempts = @numAccessesCorrect = 0
    @numActionsLogged = @numLoggableActions = 0
    @numPoliciesLogged = @numLoggablePolicies = 0
    @numtotalAccessAttempts = @numtotalAccessAttemptCorrect=0
    @numTimeouts = 0
    @logins = []
    @actions = []
    @policies = []
    @totalactions = []
    @calcDone = false
    @performDone = false
    @crlUpdated = false
    @userCreated = false
  end

  def to_s
    logged = @numAccessesCorrect
    total = @numAccessAttempts
    answer = 100
    answer = logged / total unless total == 0
    return "access attempts logged: (logged)#{logged}/(total)#{total} = #{answer}"
  end

  def score4
    @supportingData = {'numAccessesCorrect'=>@numAccessesCorrect, 'numAccessAttempts'=>@numAccessAttempts}
    if @numAccessAttempts > 0
      return (100.0 - (@numAccessesCorrect*100.0) / @numAccessAttempts).round
    else
      return 100
    end
  end
  
  def scoreText
    if @supportingData['numAccessAttempts'] == 0
#    if @summary =~ /^There weren/
      return 100 - noScore
    else
      return @score
    end
  end
  
  def raw4
    logins
  end
  
  def html4
    return self.to_s + "<br/><br/>\n" + logins.join("<br/>\n")
  end
  
  def score5
    SecurityMop2_5.instance.supportingData = {'numActionsLogged'=>@numActionsLogged, 'numLoggableActions'=>@numLoggableActions}
    if @numLoggableActions > 0
      return ((@numActionsLogged*100.0)/@numLoggableActions).round
    else
      return 0
    end
  end
  
  def raw5
    actions
  end
  
  def html5
    return SecurityMop2_5.instance.to_s + "<br/><br/>\n" + actions.join("<br/>\n")
    
  end
  
  def score6
    SecurityMop2_6.instance.supportingData = {'numPoliciesLogged'=>@numPoliciesLogged, 'numLoggablePolicies'=>@numLoggablePolicies}
    if @numLoggablePolicies > 0
      return ((@numPoliciesLogged*100.0)/@numLoggablePolicies).round
    else
      return 0
    end
  end
  
  def raw6
    policies
  end
  

  def html6
    return SecurityMop2_6.instance.to_s + "<br/><br/>\n" + policies.join("<br/>\n")
  end
  
  def setPerformDone
    @performDone=true
  end

  def getPerformDone
    return @performDone
  end

  def isCalculationDone
    return (@calcDone and @performDone)
  end

  def calculate
    @calcDone = false
    Thread.fork do
      calculateThread
    end
  end

  def calculateThread
    begin
      unless AbstractSecurityMop.waitForCompletion("2.4 Stopped")
        logInfoMsg("MOP 2.4 never completed")
        return
      end

=begin
      while ((SecurityMop2_4.instance.getPerformDone == false) && (totalWaitTime < @maxWaitTime))
        logInfoMsg "Sleeping in Calculate of SecurityMop2.4. Already slept for #{totalWaitTime}" if totalWaitTime > 0
        sleep(sleepTime) # sleep
        totalWaitTime += sleepTime
      end
=end

      totalWaitTime=0
      sleepTime=60.seconds
      if((totalWaitTime >= @maxWaitTime) && (SecurityMop2_4.instance.getPerformDone == false))
        @summary = "MOP 2.4 did not complete."
        @score = 100
        logInfoMsg "Security MOPs 2.4-2.6 did not complete."
        saveResult(false, "SecurityMop2.4", "Timeout tests incomplete") 
        saveAssertion("SecurityMop2.4", "Save results for SecurityMop2.4 Done Result failed ")
        return
      elsif (SecurityMop2_4.instance.getPerformDone == true)
        saveAssertion("SecurityMop2.4", "Saving SecurityMop2.4 test  results")
        @score = SecurityMop2_4.instance.score4
        #puts " score is #{@score}"
        @raw = SecurityMop2_4.instance.raw4
        #puts " raw is #{@raw}"
        @info = SecurityMop2_4.instance.html4
        #puts " info is #{@info}"
        if @numAccessAttempts == 0
          @summary = "There weren't any access attempts."
        else
          @summary = "There were #{@numAccessAttempts} servlet access attempts, #{@numAccessesCorrect} were correct"
          @summary = @summary + " (there were #{@numTimeouts} timeouts)" if @numTimeouts > 0
          @summary = @summary + "."
        end
        #puts "summary of result : #{@summary}"
        success = false 
        csisummary = "SecurityMop2.4 (unauthorized user actions)\n <BR> Score :#{@score}</BR>\n" 
        csisummary <<  "#{@summary}\n"
        #csisummary << "#{csiinfo}"
        if (@score == 0)
          success = true
        end
        saveResult(success, 'SecurityMop2.4', csisummary)
        saveAssertion("SecurityMop2.4", @info)
        saveAssertion("SecurityMop2.4", "Save results for SecurityMop2.4 Done")
      end
    rescue Exception => e
      saveResult(false, "SecurityMop2.4", "Error: #{e.class}")
      logInfoMsg "error in 2.4 calculate "
      logInfoMsg "#{e.class}: #{e.message}"
      logInfoMsg e.backtrace.join("\n")
    end
    @calcDone = true
  end
  
  #def cleanupOldkeys
  #  begin
  #    Dir.foreach("pems") {|x|
  #      unless x == "." or x == ".."
  #        puts "got : #{x}"
  #        File.join("pems", x)
  #        File.delete(File.join("pems", x))
  #      end
  #    }
  #    Dir.delete("pems")
  #    rescue  Exception => e
  #    message= String.new(e.message)
  #    puts "error in SecurityMop2_4.clenupold keys "
  #    puts "#{e.class}: #{e.message}"
  #    puts e.backtrace.join("\n")
  #    exit
  #  end
  #end

  def persistUserInfo
    return nil if PingSociety.isPingSociety
    agentNames = ['OSD.GOV', '1-ad-divPolicyServletManager', 'RearPolicyServletManager', 'ConusPolicyServletManager', '1-ad-divsupPolicyServletManager']
    persistedAgents = []
    agentNames.each do |agentName|
      begin
        agent = getRun.society.agents[agentName]
#        persistNow(agent, persistedAgents)
        persistNow(agent.userDomain.agent, persistedAgents)
#        persistNow(agent.caDomain.signer, persistedAgents)
      rescue Exception => e
        logInfoMsg "error while persisting"
        logInfoMsg "#{e.class}: #{e.message}"
        logInfoMsg  e.backtrace.join("\n")
      end
    end
  end

  def persistNow(agent, persistedAgents)
    begin
      if agent.class != Cougaar::Model::Agent
        logInfoMsg "couldn't persist a non-agent: agent is of class #{agent.class}"
        return false
      end
      if persistedAgents.member?(agent)
        logInfoMsg "already persisted #{agent.name}" if $VerboseDebugging
      else
        logInfoMsg "persisting #{agent.name} on node #{agent.node.name}" if $VerboseDebugging
        persistUri = agent.uri+"/persistenceMetrics?submit=PersistNow"
          logInfoMsg "  #{persistUri}" if $VerboseDebugging
        Cougaar::Communications::HTTP.get(persistUri)
        persistedAgents << agent
      end
    rescue Exception => e
      logInfoMsg "error while persisting"
      logInfoMsg "#{e.class}: #{e.message}"
      logInfoMsg  e.backtrace.join("\n")
    end
    return true
  end
  
  def setup
    #puts "Calling capture Idmefs"
    reset
    # Don't fork, to ensure setup completes before stresses
    # Thread.fork {
      begin
        captureIdmefs
        # create users, change policy, etc.
        unless @fwdDomain and @runcount==run.count
          # note: NCA agent (/editOPlan) resides in conus user domain,
          #   FwdPolicyServletAgent (/policyAdmin) resides in fwd user domain.
          ensureDomains
          #cleanupOldkeys
          if (PingSociety.isPingSociety)
            conusUsers = %w(CAndPLogistician
            PasswordLogistician CertLogistician
            DisabledLogistician DeletedLogistician
            RevokedLogistician RecreatedLogistician
            NotALogistician OtherCert
            ConusPolicyAdmin
            ConusPolicyUser FwdPolicyUser R)
            logInfoMsg "Creating users for the security MOP." if $VerboseDebugging
            @conusDomain.recreateUsers(conusUsers)
          else # !ping society
            conusUsers = %w(CAndPLogistician
               PasswordLogistician CertLogistician
               DisabledLogistician DeletedLogistician
               RevokedLogistician RecreatedLogistician
               NotALogistician OtherCert
               ConusPolicyAdmin
               ConusPolicyUser FwdPolicyUser R)
            fwdUsers = %w(FwdPolicyUser CAndPLogistician R)
            rearUsers = %w(RearPolicyUser CAndPLogistician R)
            transUsers = %w(TransPolicyUser CAndPLogistician R)
            
            logInfoMsg "Creating users for the security MOP." if $VerboseDebugging
            @fwdDomain.recreateUsers(fwdUsers)
            @rearDomain.recreateUsers(rearUsers)
            @transDomain.recreateUsers(transUsers)
            @conusDomain.recreateUsers(conusUsers)
            saveAssertion("SecurityMop2.4","created fwdUsers rearUsers transUsers conusUsers")
            
          end 

          sleep 15.seconds
          
          @conusDomain.disableUser('DisabledLogistician')
          logInfoMsg " conusDomain disable User DisabledLogistician" if $VerboseDebugging
          @conusDomain.deleteUser('DeletedLogistician')
          
          # Keep the original cert for RecreatedLogistician
          user = "ConusEnclaveCARecreatedLogistician"
          logInfoMsg " conusDomain  #{@conusDomain.agent.caDomains[0].to_s} user #{user}" if $VerboseDebugging
          File.rename("pems/#{user}_cert.pem", 'pems/RL_cert.orig.pem')
          File.rename("pems/#{user}_key.pem", 'pems/RL_key.orig.pem')
          #puts "Calling lookForCRLUpdate  "
	  lookForCRLUpdate(getOSDGOVAgent.node,"newCRL Issuer(#{getOSDGOVAgent.caDomains[0].cadn})")
	  saveAssertion("SecurityMop2.4","Looking for crl update on #{getOSDGOVAgent.node.name} with pattern newCRL Issuer(#{getOSDGOVAgent.caDomains[0].cadn})")
          revokeCertBeforeTest getOSDGOVAgent.caDomains[0],'RevokedLogistician'
          revokeCertBeforeTest @conusDomain.agent.caDomains[0],'RecreatedLogistician'
          #@conusDomain.agent.caDomains[0].revokeUserCert('RecreatedLogistician')
          @userCreated = true;          
          logInfoMsg " conus domain caDomains #{@conusDomain.agent.caDomains[0].to_s}" if $VerboseDebugging
          @conusDomain.deleteUser('RecreatedLogistician')
          logInfoMsg " conus domain deleteUse RecreatedLogistician" if $VerboseDebugging
          @conusDomain.recreateUsersForce(['RecreatedLogistician'])
          File.rename('pems/RL_cert.orig.pem', "pems/#{user}_cert.pem")
          File.rename('pems/RL_key.orig.pem', "pems/#{user}_key.pem")
          
          if(PingSociety.isPingSociety)
            [[@conusDomain,'CONUS']].each do |domainandname|
              domain = domainandname[0]
              logInfoMsg " Security Mop 2-4 setup domain is #{domain}" if $VerboseDebugging
              name = domainandname[1]
              auth = 'EITHER'
              logInfoMsg "Domain #{domain} Name : #{name}" if $VerboseDebugging
              u = UserClass.new("P", "P", auth, 'policy', 'User', ["PolicyAdministrator"])
              #puts "user created is : #{u.to_s}"
              logInfoMsg "calling domain recreateUsers" if $VerboseDebugging
              domain.recreateUsers([u])
            end
          else # !ping society
            [[@fwdDomain,'Fwd'], [@rearDomain,'Rear'], [@transDomain,'Trans']].each do |domainandname|
              domain = domainandname[0]
              name = domainandname[1]
              auth = 'EITHER'
              u = UserClass.new("P", "P", auth, 'policy', 'User', ["PolicyAdministrator"])
              domain.recreateUsers([u])
            end
          end
          logInfoMsg "Completed MOP 2.4 setup" if $VerboseDebugging
          AbstractSecurityMop.finished('MOP2.4 Setup')
        end
      rescue => ex
        saveAssertion('SecurityMop2.4 Setup failed ',
                      "Unable to perform stress: #{ex}\n#{ex.backtrace.join("\n")}" )
      end 
    # } # Thread.fork
  end # setup

  def lookForCRLUpdate(node,pattern) 
    run.comms.on_cougaar_event do |event|
      checkCrlUpdateEvent(event,node,pattern )
    end
  end

  def checkCrlUpdateEvent(event,node,pattern)
    if ((event.component == 'CRLCache') && (event.node == node.name) &&  (event.data.include? pattern) &&  (@crlUpdated == false) )
      puts "GOT CRL update for Node----> #{node.name}" if $VerboseDebugging
      @crlUpdated = true
    end
  end
  
  def captureIdmefs
    @found = false
    @events = []
    onCaptureIdmefs do |event|
      e = event.to_s
      @events.push(e) unless @found
      if e =~ @idmefPattern
        @found = true
        @events = []
      end
    end
  end

  def searchForLoginFailure(pattern)
    @events = []
    @idmefPattern = pattern
    @found = false
  end

  def waitForLoginFailure(timeoutlen)
    1.upto(timeoutlen) do |n|
      return true if @found
      sleep 1.second
    end
    return false
  end

  def doRunPeriodically
#    return true
    return false
  end

  def perform
    Thread.fork {
      begin
        #puts "Starting Perform thread SecurityMop 2.4"
        logInfoMsg "SecurityMop2_4.perform will now wait for completion of MOP 2.4 setup" if $VerboseDebugging

	if AbstractSecurityMop.waitForCompletion('MOP2.4 Setup')
	  saveAssertion("SecurityMop2.4","in Perfom calling ensureDomains")
	  ensureDomains
	  logInfoMsg " CALLING Perform TESTS FOR SECURITY MOP " if $VerboseDebugging
	  #revokeCertBeforeTest
	  #puts "sleeping for 3 minutes"
	  #sleep 3.minutes
	  #saveAssertion("SecurityMop2.4","Calling run test ")
	  maxSleepTime=20.minutes
	  sleepTime = 1.minutes
	  totalWaitTime = 0
	  #puts "Starting to wait for CRL Update" 
	  while @userCreated == false && totalWaitTime < maxSleepTime
            logInfoMsg "Waited #{totalWaitTime} minutes  for User Creation" if $VerboseDebugging
	    saveAssertion "SecurityMop2.4", "Waited #{totalWaitTime} minutes  for User Creation"
	    sleep(sleepTime) # sleep
	    totalWaitTime += sleepTime 
	  end
	  if ((totalWaitTime >= maxSleepTime) && (@UserCreation == false) )
	    saveResult(false, "SecurityMop 2.4", "Timeout Could not create Users ")
	  end
	  maxSleepTime=4.minutes
	  sleepTime = 10.seconds
	  totalWaitTime = 0
	  while @crlUpdated == false && totalWaitTime < maxSleepTime
	    logInfoMsg "Waited #{totalWaitTime} seconds for CRL update" if $VerboseDebugging
	    sleep(sleepTime) # sleep
	    totalWaitTime += sleepTime 
	  end
	  if ((totalWaitTime >= maxSleepTime) && (@crlUpdated == false) )
	    saveResult(false, "SecurityMop 2.4", "Timeout Didn't receive CRL Update")
	  elsif @crlUpdated == true
	    saveAssertion("SecurityMop2.4","Calling run Tests after CRL Update ")
	  end
	  runTests(@tests)
#	  runServletPolicyTests
          AbstractSecurityMop.finished("2.4 Stopped") # if Cougaar::Actions::InitiateSecurityMopCollection.halted?
          logInfoMsg " SECURITY MOP 2.4 COMPLETED ONE CYCLE " if $VerboseDebugging
          AbstractSecurityMop.finished('MOP2.4 Performed Once')
          AbstractSecurityMop.finished(self.class)
          setPerformDone

          while (!Cougaar::Actions::InitiateSecurityMopCollection.halted?)
            quitTime = Time.now + 4.minutes
            while (!Cougaar::Actions::InitiateSecurityMopCollection.halted? and Time.now<quitTime)
              sleep 10.seconds
            end
            runTests(@tests)
            # No longer require to run these test as they are added as part of Conus test use case 1A5 and 1A51
            #runServletPolicyTests
          end

	else
          logInfoMsg "MOP2.4 setup never completed; skipping execution of MOP2.4"
          AbstractSecurityMop.finished('MOP2.4 Perform')
          AbstractSecurityMop.finished(self.class)
        end
      rescue Exception => e
        logInfoMsg "error in perform"
        logInfoMsg "#{e.class}: #{e.message}"
        logInfoMsg e.backtrace.join("\n")
      end
    }
  end


  def revokeCertBeforeTest (mycadomain,user)
    mycadomain.revokeUserCert(user)
  end

  def runRevokedCertTests
  end

  def runServletPolicyTests
    # this is no longer used because the policy propagation during stress could cause problems
    logInfoMsg " CALLING Policy TESTS FOR SECURITY MOP " if $VerboseDebugging
    enclave = getOSDGOVAgent.enclave
    logInfoMsg "Changing policy for #{enclave} to passwd " if $VerboseDebugging
    passwdpol = getPasswordServletPolicy
    deltaPolicy(enclave, passwdpol)
    tests = getPasswdPolicyTests
    runTests(tests)
    certpol = getCertServletPolicy
    deltaPolicy(enclave, certpol)
    sleep 1.minutes
    tests =getCertPolicyTests
    runTests(tests)
  end  

  def ensureDomains
    logInfoMsg "ensureDomains of SecurityMop 2_4 called " if $VerboseDebugging
    #logInfoMsg "ensureDomains of SecurityMop 2_4 called "
    unless defined?(@conusDomain) and @conusDomain.kind_of?(UserDomain)
      UserDomains.instance.ensureUserDomains
      CaDomains.instance.ensureExpectedEntities
      @conusDomain = UserDomains.instance['ConusUserDomainComm']
      @fwdDomain = UserDomains.instance['1-ad-divUserDomainComm']
      @rearDomain = UserDomains.instance['RearUserDomainComm']
      @transDomain = UserDomains.instance['1-ad-divsupUserDomainComm']
      saveAssertion("SecurityMop2.4", "calling get Tests");
      @tests = getTests
      logInfoMsg "ensureDomains of SecurityMop 2_4  Test returned #{@test} " if $VerboseDebugging
      saveAssertion("SecurityMop2.4"," tests : #{@tests}")
      saveAssertion("SecurityMop2.4"," test size : #{@tests.size}")
      saveAssertion("SecurityMop2.4", "get Tests Done")
    end
  end


  def runTests(tests)
    logInfoMsg "Run test called with size :#{tests.size}" if $VerboseDebugging
    #logInfoMsg "Run test called with size :#{tests.size}"
    saveAssertion("SecurityMop2.4", "runTests called ");
    tests.each do |domain, testSet|
      # break out of the loop if the halt flag has been set
      # The getPerformDone will wait for one complete set to be run. Don't use this because
      # can extend the length of a run and affect the performance mop.
      break if Cougaar::Actions::InitiateSecurityMopCollection.halted?  # and getPerformDone
      testSet.each do |test|
        break if Cougaar::Actions::InitiateSecurityMopCollection.halted?  # and getPerformDone
        type=test[0]
        agent=test[1]
        user=test[2]
        password=test[3]
        servlet=test[4]
        useCase=test[6]
        idmefPattern=test[7]
        scope=test[8]

        # skip this agent if it isn't alive
        # note: CSI's ping society doesn't have agent.running? method
        agentIsRunning = (PingSociety.isPingSociety or agent.running?)
        userAdminIsRunning = (PingSociety.isPingSociety or agent.userDomain.agent.running?)
        if !agentIsRunning or !userAdminIsRunning
          # agentIsKilled = (PingSociety.isPingSociety or agent.killed?)
          begin
            msg = "Skipping agent #{agent.name}, test #{test[2..-1].inspect}, #{test[0]} because agent is not running (#{!agentIsRunning}) or the user admin agent is not running (#{!userAdminIsRunning})"
            saveAssertion("n/a", msg)
            logInfoMsg msg if $VerboseDebugging
          rescue Exception => e
            logInfoMsg "couldn't log ignored msg in runTests"
          end
          next
        end

        if scope !=nil
          scopeString =String.new(scope)        
          if (scopeString.include? "SecurityMop2.4")
            mop24=true
          end 
          if (scopeString.include? "SecurityMop2.6")
            mop26=true
          end
          #bmd
          #if (scopeString.include? "SecurityMop2.5") or (scopeString.include? "-")
          #if (scopeString.include? "SecurityMop2.5")
          #  mop25=true
          #end
        else
          mop24=false
          mop26=false
          mop25=false;
        end

        #bmd
        # All access attempts apply to mops 2.4 and 2.5
        mop24 = mop25 = true

        if $VerboseDebugging
          logInfoMsg "type --> #{type}"
          logInfoMsg "agent --> #{agent.name}"
          logInfoMsg "user --> #{user}"
          logInfoMsg "password --> #{password}"
          logInfoMsg "servlet --> #{servlet}"
          logInfoMsg "useCase --> #{useCase}"
          logInfoMsg "idmefPattern --> #{idmefPattern}"
          logInfoMsg "scope --> #{scope}"
        end
        begin
          pattern = /#{agent.host.name}.*#{servlet}.*#{idmefPattern}/
          searchForLoginFailure(pattern) if scope
          # note: result is true/false
          @numtotalAccessAttempts +=1
          result, expectedResult, actualResult, successBoolean, msg, body = domain.accessServletMop(test)
          if $VerboseDebugging
            logInfoMsg "servlet --> #{servlet}"
            logInfoMsg "useCase --> #{useCase}"
            logInfoMsg " expectedResult -----> #{expectedResult}"
            logInfoMsg " actualResult -----> #{actualResult}"
            logInfoMsg " successBoolean----->#{successBoolean}"
            logInfoMsg "idmefPattern --> #{idmefPattern}"
          end
          if useCase == nil
            saveAssertion('No use Case Specified ',msg)
          else
            saveAssertion(useCase,msg)
          end
          if !successBoolean
            saveAssertion(useCase,
                          " FAILED TEST :  expectedResult:#{expectedResult} actual:#{actualResult} success:#{successBoolean} scope:#{scope}, #{expectedResult.class}, #{actualResult.class}, #{agent.host.name}, #{servlet}, #{user}, #{password}")

          end
          if $VerboseDebugging
            logInfoMsg " expectedResult:#{expectedResult} actual:#{actualResult} success:#{successBoolean} idmefPattern:#{idmefPattern} scope:#{scope}, #{expectedResult.class}, #{actualResult.class}"
          end
          if [404,493,494].member?(actualResult) # no web server or timed out 
            msg = "ignored (no web server or timed out) at #{agent.host.name}:  #{msg}"
            @totalactions << "Web server Time out (#{actualResult}) : #{body}"
            # @actions << msg if scope =~ /user/
            # @policies << msg if scope =~ /policy/
            #@actions << msg
            logInfoMsg "  #{msg}" if $VerboseDebugging
            next
          end
         #@numAccessAttempts += 1
          httpsRedirect = false
          httpsRedirect = true if actualResult == 491 and expectedResult == 491
          @actions << msg if !successBoolean
          if expectedResult==200
            @numtotalAccessAttemptCorrect+=1
          end

          if actualResult == 492   # attempt timed out
            userAdminIsRunning = (PingSociety.isPingSociety or agent.userDomain.agent.running?)
            if userAdminIsRunning
              # applies to mops 2.5 and 2.6 (not 2.4)
              @numTimeouts += 1
              @logins << "Ignored time out: #{msg}"
              msg = "Failure: No IDMEF for timeout: #{msg}"
              @numLoggableActions += 1 if mop25
              @actions << msg if mop25
              @numLoggablePolicies += 1  # 2.6
              @policies << msg
#bmd
# sleep 1.minute if $VerboseDebugging   # just to see if there are any events coming in
              logInfoMsg "@events: #{@events.inspect}" if $VerboseDebugging
            else
              # ignore attempt when the user admin agent is down
              begin
                msg = "Ignoring already executed attempt on agent #{agent.name}, test #{test[2..-1].inspect}, #{test[0]} because the user admin agent just died"
                saveAssertion("n/a", msg)
                logInfoMsg msg if $VerboseDebugging
                next
              rescue Exception => e
                logInfoMsg "couldn't log ignored msg in runTests"
              end
            end

          elsif actualResult == 200
            msg = "Success: #{msg}"
            @logins << msg
            @actions << msg if mop25
            @numAccessAttempts += 1   # 2.4
            @numLoggableActions += 1 if mop25
            if expectedResult == 200
              @numtotalAccessAttemptCorrect += 1
              @numAccessesCorrect += 1  # 2.4
              @numActionsLogged += 1 if mop25
              @actions << " #{msg}"
            end   
            logInfoMsg  "logged:  #{msg}" if $VerboseDebugging

          else
            if (mop25)
              if expectedResult == 200
                @actions << "Failure: User Denied Access   #{msg}"
              end
            end
            # setting the waittime for Idmef events to 2 minutes as it is possible 
            # that syatem will take lot more time if it is running with some kind of stress  
            waitTime=120
            if httpsRedirect
              suc = true
            else
              suc = waitForLoginFailure(waitTime)
   logInfoMsg "@events: #{@events.inspect}" if !suc and $VerboseDebugging
            end
            if (mop24)   # scope =~ /user/
              @numAccessAttempts += 1    # 2.4
              @numLoggableActions += 1   # 2.5
              if successBoolean
                @numAccessesCorrect += 1 # 2.4
                @numActionsLogged += 1   # 2.5
                @numtotalAccessAttemptCorrect+=1
                @logins << " #{msg}"
                #logInfoMsg  "Success :  #{msg}"
              else
                if useCase!=nil
                  @logins << "Failure : test case #{useCase}  #{msg}" 
                  saveAssertion(useCase, "Failure :test case #{useCase}   #{msg}")
                else 
                  @logins << "Failure : User Allowd Access   #{msg}" 
                  saveAssertion("No use case specified", "Failure : User Allowd Access    #{msg}")
                end
              end
            end
            if (mop26)   # scope =~ /policy/
              @numLoggablePolicies += 1  # 2.6
              if suc
                @numPoliciesLogged += 1
                @numtotalAccessAttemptCorrect+=1
                @policies << " Success : #{msg}"
              else
                @policies << " Failure No IDMEF Generated for #{useCase} : #{msg}"
                saveAssertion(useCase,"  Failure No IDMEF Generated for #{useCase} SecurityMop2.6 expectedResult:#{expectedResult} actual:#{actualResult} idmefPattern:#{idmefPattern} NOT Found")
              end
            end
          end # if actualResult == 200
          if $VerboseDebugging
            logInfoMsg "$                 numAccessesCorrect            #{@numAccessesCorrect} "
            logInfoMsg "$                 numAccessAttempts             #{@numAccessAttempts}  "
            logInfoMsg "$                 Actions logged                #{@numActionsLogged}   "
            logInfoMsg "$                 Loggable Action               #{@numLoggableActions} "
            logInfoMsg "$                 policy  logged                #{@numPoliciesLogged}  "
            logInfoMsg "$                 policy  loggable              #{@numLoggablePolicies}"
          end
        rescue Exception => e
          logInfoMsg "error in runTests"
          logInfoMsg "#{e.class}: #{e.message}"
          logInfoMsg  e.backtrace.join("\n")
        end

        if @numLoggablePolicies == $MinimumUnauthorizedServletAttempts
          unless AbstractSecurityMop.member?('CompletedMinimumUnauthorizedServletAttempts')
            persistUserInfo
            AbstractSecurityMop.finished('CompletedMinimumUnauthorizedServletAttempts')
          end
        end
        # An idmef won't be generated if a similar one has been sent within the last six seconds.
        # This sleep will prevent this from being a problem.
        sleep 6.seconds
      end # testSet.each
    end # tests.each
    #logInfoMsg "done with runTests" if $VerboseDebugging
    #logInfoMsg "logins----------------------------->   #{@logins}"
    #logInfoMsg "action----------------------------->   #{@actions}"
    #logInfoMsg "policies----------------------------->   #{@policies}"
    logInfoMsg "done with runTests" if $VerboseDebugging
  end # runTests
  
  def getPasswdPolicyTests
    
     begin
       #logInfoMsg "calling getPasswdPolicyTests "
       testCollection = {}
       testCollection[@conusDomain] =getpolicyPasswdTest
       return testCollection
     rescue Exception => e
       logInfoMsg "error in SecurityMop2_4.getPasswdPolicyTests"
       logInfoMsg "#{e.class}: #{e.message}"
       logInfoMsg e.backtrace.join("\n")
     end
       
  end
  
   def getCertPolicyTests
     begin
       #logInfoMsg "calling getCertPolicyTests "
       testCollection = {}
       testCollection[@conusDomain] =getpolicyCertTest
       return testCollection
     rescue Exception => e
       logInfoMsg "error in SecurityMop2_4.getCertPolicyTests"
       logInfoMsg "#{e.class}: #{e.message}"
       logInfoMsg e.backtrace.join("\n")
     end
       
  end


  def getTests
    begin
      fwdAgent   = run.society.agents['1-ad-divPolicyServletManager']
      rearAgent  = run.society.agents['RearPolicyServletManager']
      conusAgent = run.society.agents['ConusPolicyServletManager']
      transAgent = run.society.agents['1-ad-divsupPolicyServletManager']
      @fwdAgent   = fwdAgent
      logInfoMsg "run:#{run}, #{fwdAgent}" if $VerboseDebugging
      
      if (PingSociety.isPingSociety)
        unless fwdAgent or rearAgent or conusAgent or transAgent
          raise " PolicyServletManager agents is missing for  [Fwd|Rear|Conus|Trans]"
        end
        conusUser = "ConusPolicyUser"
        rearUser  = "RearPolicyUser"
        logInfoMsg "calling test on conus user " if $VerboseDebugging
        testCollection = {}
        [[@conusDomain, conusAgent, conusUser, rearUser]].each do |x|
          domain = x.shift
          testCollection[domain] = self.send(:testSet, *x)
        end
        testCollection[@conusDomain] += conusTests
        return testCollection
      else
        unless fwdAgent and rearAgent and conusAgent and transAgent
        raise "One of the PolicyServletManager agents is missing [Fwd|Rear|Conus|Trans]"
        end
        fwdUser   = "FwdPolicyUser"
        rearUser  = "RearPolicyUser"
        conusUser = "ConusPolicyUser"
        transUser = "TransPolicyUser"
        testCollection = {}
        [[@fwdDomain,   fwdAgent,   fwdUser,   rearUser],
          [@rearDomain,  rearAgent,  rearUser,  transUser],
          [@conusDomain, conusAgent, conusUser, fwdUser],
          [@transDomain, transAgent, transUser, conusUser]].each do |x|
          domain = x.shift
          testCollection[domain] = self.send(:testSet, *x)
        end
	
        testCollection[@conusDomain] += conusTests
        saveAssertion("SecurityMop2.4","Returing test size :#{testCollection.size}") 
	logInfoMsg " get test returning test size :#{testCollection.size}" if $VerboseDebugging
	return testCollection
      end 
    rescue Exception => e
      logInfoMsg "error in SecurityMop2_4.getTests"
      logInfoMsg "#{e.class}: #{e.message}"
      logInfoMsg e.backtrace.join("\n")
    end
    #return testCollection
  end # def getTests


  def testSet(agent, user, otherUser)

    if $VerboseDebugging  
      logInfoMsg "agent: #{agent.name}, #{user}, #{otherUser}" if $VerboseDebugging 
      logInfoMsg "Test set called with ------------->> >>   agent: #{agent.name}, #{user}, #{otherUser}"
    end
    saveAssertion("SecurityMop2.4","Test set called with ------------->> >>   agent: #{agent.name}, #{user}, #{otherUser}")
    agent = run.society.agents[agent] if agent.kind_of?(String)
    if( agent.userDomain ==nil)
      logInfoMsg " Cannot create test set for agent #{agent.name} user#{user} #{otherUser}"
      saveAssertion("SecurityMop2.4"," Cannot create test set for agent #{agent.name} user#{user} #{otherUser}")
      return;
    end
    domainName = agent.userDomain.name
    policyServlet = '/policyAdmin'
    tests = [
      # auth    agent  user   password   servlet  expectedResponse
      ['Basic', agent, user,  user,       policyServlet,  200 ,   '1A101',    '',                             'SecurityMop2.5'],
      ['Cert',  agent, user,  true,       policyServlet,  200 ,   '1A103',    '',                             'SecurityMop2.5'],
      ['Basic', agent, user, 'badpasswd', policyServlet,  401 ,   '1A1-1A20', 'WRONG_PASSWORD',               'SecurityMop2.4-SecurityMop2.6'],
      ['Cert',  agent, user,  false,      policyServlet,  403 ,   '1A2-1A21', 'INSUFFICIENT_PRIVILEGES',      'SecurityMop2.4-SecurityMop2.6']
    ]
    
    logInfoMsg "test size returned in test set is #{tests.size} " if $VerboseDebugging 
    return tests
  end # testSet
  
  def getOSDGOVAgent
    run.society.each_agent(true) { |agent|
      agent.each_facet("org_id") { |facet| 
        if facet["org_id"] == "OSD.GOV"
          return agent
        end
      }
    }
  end
  
  
  def getpolicyPasswdTest
    osdgovAgent = getOSDGOVAgent
    servlet = '/TestUserPolicy'
    cAndPLog = 'CAndPLogistician'
    tests = [
      ['Cert',    osdgovAgent,    cAndPLog,    true,    servlet,    401,    '1A51-1A241',     'INSUFFICIENT_PRIVILEGES',     'SecurityMop2.4-SecurityMop2.6']
    ]
    return tests
  end

  def getpolicyCertTest
    osdgovAgent = getOSDGOVAgent
    servlet = '/TestUserPolicy'
    cAndPLog = 'CAndPLogistician'
    tests = [
      ['Basic',   osdgovAgent,    cAndPLog,    cAndPLog,    servlet,    491,    '1A5-1A24',   '',    'SecurityMop2.4-SecurityMop2.6']
    ]
    return tests
  end
  

  def conusTests
    osdgovAgent = getOSDGOVAgent
    servlet = '/TestUserPolicy'
    servletpasswd = '/TestPasswordPolicy'
    servletcert = '/TestCertPolicy'
    
    cAndPLog = 'CAndPLogistician'
    certLog = 'CertLogistician'
    passwdLog = 'PasswordLogistician'
    disabledLog = 'DisabledLogistician'
    deletedLog = 'DeletedLogistician'
    revokedLog = 'RevokedLogistician'
    recreatedLog = 'RecreatedLogistician'
    notALog = 'NotALogistician'
    otherCert = 'OtherCert'
    notAUser = 'NotAUser'
    badPassword = 'CertLogistician' # valid passwd for different user
    policyServlet = '/policyAdmin'
    if (PingSociety.isPingSociety) 
      policyAgent =  run.society.agents['ConusPolicyDomainManager']
    else
      policyAgent = run.society.agents['FwdPolicyDomainManager']
      fwdAdmin = 'FwdPolicyAdmin'
      remoteFwdAdmin = 'ConusUserDomainComm\\R'
      fwdAdminFromConus2 = 'ConusUserDomainComm\FwdPolicyAdminFromConus'
      conusAdmin = 'ConusPolicyAdmin'
      rearPolicyAgent = run.society.agents['RearPolicyDomainManager']
      transPolicyAgent = run.society.agents['TransPolicyDomainManager']
    end
    tests = [
      ['Basic',    osdgovAgent,    cAndPLog,    cAndPLog,    servlet,    200,    '1A101',     '',                           'SecurityMop2.5'],
      ['Cert',     osdgovAgent,    cAndPLog,    true,        servlet,    200,    '1A103',     '',                           'SecurityMop2.5'],

      #1A1 and 1A20
      ['Basic',    osdgovAgent,    cAndPLog,    badPassword, servlet,    401,    '1A1-1A20',  'WRONG_PASSWORD',             'SecurityMop2.4-SecurityMop2.6'],

      #1A2 and 1A21 
      ['Cert',     osdgovAgent,    cAndPLog,    false,       servlet,    403,    '1A2-1A21',  'INSUFFICIENT_PRIVILEGES',    'SecurityMop2.4-SecurityMop2.6'],

      #1A4 and 1A23 
      ['Cert',     osdgovAgent,    revokedLog,  true,        servlet,    403,    '1A4-1A23',  'INVALID_USER_CERTIFICATE',   'SecurityMop2.4-SecurityMop2.6'],
      ['Basic',    osdgovAgent,    revokedLog,  revokedLog,  servlet,   491,    '1A41-1A231','INVALID_USER_CERTIFICATE',   'SecurityMop2.4-SecurityMop2.6'],

      #1A6 and 1A25 
      ['Basic',    osdgovAgent,    certLog,     certLog,     servlet,    491,    '1A6-1A25',  'WRONG_PASSWORD',             'SecurityMop2.4-SecurityMop2.6'], 

      ['Cert',     osdgovAgent,    certLog,     true,        servlet,    200,    '1A103',    '',                            'SecurityMop2.5'],




      ['Basic',    osdgovAgent,    passwdLog,   passwdLog,   servlet,    200,    '1A101',    '',                            'SecurityMop2.5'], 
      ['Cert',     osdgovAgent,    passwdLog,   true,        servlet,    200,    '1A103',    '',                            'SecurityMop2.5'], 
      
      #1A7 and 1A26 
      ['Basic',    osdgovAgent,    deletedLog,  deletedLog,  servlet,    401,    '1A7-1A26',  'USER_DOES_NOT_EXIST',        'SecurityMop2.4-SecurityMop2.6'],

      #1A8 and 1A27 
      ['Cert',     osdgovAgent,    deletedLog,  true,        servlet,    403,    '1A8-1A27', 'USER_DOES_NOT_EXIST',         'SecurityMop2.4-SecurityMop2.6'],

      #1A9 and 1A28 
      ['Basic',    osdgovAgent,    disabledLog, disabledLog, servlet,    401,    '1A9-1A28',  'DISABLED_ACCOUNT',           'SecurityMop2.4-SecurityMop2.6'],

      #1A10 and 1A29 
      ['Cert',    osdgovAgent,    disabledLog, true,        servlet,     401,    '1A10-1A29', 'DISABLED_ACCOUNT',           'SecurityMop2.4-SecurityMop2.6'],
      
      ['Cert',    osdgovAgent,    cAndPLog,    true,     servletpasswd,    403,    '1A51-1A241',     'INSUFFICIENT_PRIVILEGES',     'SecurityMop2.4-SecurityMop2.6'],

      ['Basic',   osdgovAgent,    cAndPLog,    cAndPLog,    servletcert,   491,    '1A5-1A24',   '',    'SecurityMop2.4-SecurityMop2.6'],

      ['Cert',    osdgovAgent,    cAndPLog,    true,     servletcert,      200,    '1A51-1A241',     '',     'SecurityMop2.5'],

      ['Basic',   osdgovAgent,    cAndPLog,    cAndPLog,    servletpasswd, 200,    '1A5-1A24',   '',    'SecurityMop2.5']
      
      

      #['Basic',   osdgovAgent,    notALog,     notAUser,    servlet,     401,    '1A11-1A30', 'WRONG_PASSWORD',             'SecurityMop2.4-SecurityMop2.6'],
      #['Cert',    osdgovAgent,    notALog,     true,        servlet,     401,    '1A12-1A30', 'INSUFFICIENT_PRIVILEGES',    'SecurityMop2.4-SecurityMop2.6'],
    ]   
=begin 
       #tests = [
       #  ['Basic', osdgovAgent,    cAndPLog,     cAndPLog,        servlet,          200 ,        '1A101',    ,'' ,             'SecurityMop2.5'],
       #  ['Cert',  osdgovAgent,    cAndPLog,     true,            servlet,          200,         '1A103'     ,'' ,             'SecurityMop2.5' ],
       #  #1A1 and 1A20
       #  ['Basic', osdgovAgent,    cAndPLog,     badPassword,     servlet,          401,         '1A1/1A20', 'WRONG_PASSWORD', 'SecurityMop2.4-SecurityMop2.6'],
       #  #1A2 and 1A21
       #  ['Cert',  osdgovAgent,    cAndPLog,     false,           servlet,          401,         '1A2/1A21', 'WRONG_PASSWORD', 'Mop2.4-Mop2.6'],
       #  #
       #  ['Cert',  osdgovAgent,    revokedLog,   true,            servlet,          401,         '12a',      'REVOKED_USER',   'user'],
       #  ['Basic', osdgovAgent,    passwdLog,    passwdLog,        servlet,          200,         '1A101'],
       #  ['Cert',  osdgovAgent,     passwdLog,    true,                  servlet,           200,         '1A103'],
       #  ['Basic', osdgovAgent,    certLog,         certLog,             servlet,           491,         '1A5/1A24',           'WRONG_PASSWORD',       'Mop2.4/Mop2.6'],
       # ['Cert',  osdgovAgent,     certLog,         true,                  servlet,           200,        '1A103'                                                     ],
       #  ['Basic', osdgovAgent,    notALog,        notAUser,           servlet,           401,          '1A7',                   'WRONG_PASSWORD',       'Mop2.4/Mop2.6'],
       #  ['Basic', osdgovAgent,    notALog,         notAUser,          servlet,           401,          '10a',                   'WRONG_PASSWORD',        'user'],
       #  ['Basic', osdgovAgent, disabledLog,  disabledLog,  servlet,  401, '11a','DISABLED_ACCOUNT','user'],
       # ['Cert',  osdgovAgent, disabledLog,  true,         servlet,  401, '11c','DISABLED_ACCOUNT','user'],
       #  ['Basic', osdgovAgent, deletedLog,   deletedLog,   servlet,  401, '11e','USER_DOES_NOT_EXIST','user'],
       #  ['Cert',  osdgovAgent, deletedLog,   true,         servlet,  403, '11g','USER_DOES_NOT_EXIST','user'],
       #  # try to use a previously created cert
       #  ['Cert',  osdgovAgent, recreatedLog, true,         servlet,  401, '13a','WRONG_PASSWORD','user']
       #  ###['Cert',  osdgovAgent, otherCert,    true,      servlet,  401, '14a','WRONG_PASSWORD','user']
       # ]    
=end
    return tests

    
  end # conusTests
  
=begin
     
     ['Basic', policyAgent, fwdAdmin,           fwdAdmin, policyServlet,  200],
       ['Basic', policyAgent, remoteFwdPolicy,  remoteFwdAdmin, policyServlet,  401],
       ['Basic', policyAgent, fwdAdminFromConus2, fwdAdmin, policyServlet,  401],
       
       ['Basic', rearPolicyAgent, fwdAdmin,           fwdAdmin, policyServlet,  200],
       ['Basic', rearPolicyAgent, fwdAdminFromConus,  fwdAdmin, policyServlet,  401],
       ['Basic', rearPolicyAgent, fwdAdminFromConus2, fwdAdmin, policyServlet,  401],
       
       ['Basic', transPolicyAgent, fwdAdmin,           fwdAdmin, policyServlet,  200],
       ['Basic', transPolicyAgent, fwdAdminFromConus,  fwdAdmin, policyServlet,  401],
       ['Basic', transPolicyAgent, fwdAdminFromConus2, fwdAdmin, policyServlet,  401],
       
=end

=begin
     user pass cert
     ---- ---- ---- successes
     -    -
       -         -
       >    -
       >         -
       -------------- failures
     -    x
     -         x
     d    -
       d         -
       ......

       --------------
       >  user from another domain
     n  not a created user
     r  recreated
     v  revoked
     k  deleted (killed)
     d  disabled

=end


  def getPasswordServletPolicy
    passwdpolicy= "Delete CertPolicyServletAuth
   Policy PasswordPolicyServletAuth  = [ 
      ServletAuthenticationTemplate
  All users must use Password  authentication when accessing the servlet named TestUserPolicyServlet
]"

    return passwdpolicy
  end

  def getCertServletPolicy
    certpolicy= "Delete PasswordPolicyServletAuth
       Policy CertPolicyServletAuth  = [ 
       ServletAuthenticationTemplate
       All users must use CertificateSSL  authentication when accessing the servlet named TestUserPolicyServlet
]"

    return certpolicy
  end

  def getOriginalServletPolicy
    originalpolicy= "Policy OriginalPolicyServletAuth  = [ 
      ServletAuthenticationTemplate
   All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named TestUserPolicyServlet
]"

    return passwdpolicy
  end

end # class SecurityMop2_4

