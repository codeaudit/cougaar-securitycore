
require 'security/lib/AbstractSecurityMop'
require 'security/lib/SecurityMop2_5'
require 'security/lib/rules'
require 'security/lib/userDomain'
require 'security/lib/policy_util'


class  SecurityMop2_4 < AbstractSecurityMop
  include Singleton
  attr_accessor :numAccessAttempts, :numAccessesCorrect, :logins
  attr_accessor :numActionsLogged, :numLoggableActions, :actions
  attr_accessor :numPoliciesLogged, :numLoggablePolicies, :policies

  #def initialize(run)
  #  super(run)
  #  reset
  #  removePemCertificates
  #  @name = "2-4"
  #  @descript = "Percentage of user actions that were available for invocation counter to authorization policy"
  #end
  def initialize()
    # super(run)
    reset
    removePemCertificates
    @name = "2.4"
    @descript = "Percentage of user actions that were available for invocation counter to authorization policy"
  end

  def getStressIds()
    return ["SecurityMop2.4"]
  end

  def removePemCertificates
    `rm -f pems/*.pem` unless $WasRunning
  end

  def reset
    @numAccessAttempts = @numAccessesCorrect = 0
    @numActionsLogged = @numLoggableActions = 0
    @numPoliciesLogged = @numLoggablePolicies = 0
    @logins = []
    @actions = []
    @policies = []
  end

  def to_s
    logged = @numAccessesCorrect
    total = @numAccessAttempts
    answer = 100
    answer = logged / total unless total == 0
    return "access attempts logged: (logged)#{logged}/(total)#{total} = #{answer}"
  end

  def score4
    if @numAccessAttempts > 0
      return (@numAccessesCorrect*100.0) / @numAccessAttempts
    else
      return 100.0
    end
  end
  
  def scoreText
    if @summary =~ /^There weren/
      return NoScore
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
    if @numLoggableActions > 0
      return (@numActionsLogged*100.0)/@numLoggableActions
    else
      return 100.0
    end
  end
  
  def raw5
    actions
  end
  
  def html5
    return SecurityMop2_5.instance.to_s + "<br/><br/>\n" + actions.join("<br/>\n")
    
  end
  
  def score6
    if @numLoggablePolicies > 0
      return (@numPoliciesLogged*100.0)/@numLoggablePolicies
    else
      return 100.0
    end
  end
  
  def raw6
    policies
  end
  
  def html6
    return SecurityMop2_6.instance.to_s + "<br/><br/>\n" + policies.join("<br/>\n")
  end

  def calculate
    begin
      @score = SecurityMop2_4.instance.score4
      puts " score is #{@score}"
      @raw = SecurityMop2_4.instance.raw4
      puts " raw is #{@raw}"
      @info = SecurityMop2_4.instance.html4
      puts " info is #{@info}"
      if @numAccessAttempts == 0
      @summary = "There weren't any access attempts."
      else
        @summary = "There were #{@numAccessAttempts} servlet access attempts, #{@numAccessesCorrect} were correct."
      end
      puts "summary of result : #{@summary}"
      sucess = false 
      if (@score == 100.0)
        success = true
      end
      saveResult(success, 'mop2.4',@summary)
      @calculationDone = true
    rescue Exception => e
      puts "error in 2.4 calculate "
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
      exit
    end
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
  
  def setup
    #puts "Calling capture Idmefs"
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
      else 
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
        saveAssertion("SecurityMop-2.4","creating fwdUsers rearUsers transUsers conusUsers")
      end 

      sleep 15.seconds

      @conusDomain.disableUser('DisabledLogistician')
      puts " conusDomain disableUser DisabledLogistician" if $VerboseDebugging
      @conusDomain.deleteUser('DeletedLogistician')

      # Keep the original cert for RecreatedLogistician
      user = "ConusEnclaveCARecreatedLogistician"
      puts " conusDomain  #{@conusDomain.agent.caDomains[0].to_s} user #{user}" if $VerboseDebugging
      File.rename("pems/#{user}_cert.pem", 'pems/RL_cert.orig.pem')
      File.rename("pems/#{user}_key.pem", 'pems/RL_key.orig.pem')
      
      revokeCertBeforeTest getOSDGOVAgent.caDomains[0],'RevokedLogistician'
      revokeCertBeforeTest @conusDomain.agent.caDomains[0],'RecreatedLogistician'
      #@conusDomain.agent.caDomains[0].revokeUserCert('RecreatedLogistician')
      
      
      puts " conus domain caDomains #{@conusDomain.agent.caDomains[0].to_s}" if $VerboseDebugging
      @conusDomain.deleteUser('RecreatedLogistician')
      puts " conus domain deleteUse RecreatedLogistician" if $VerboseDebugging
      @conusDomain.recreateUsersForce(['RecreatedLogistician'])
      File.rename('pems/RL_cert.orig.pem', "pems/#{user}_cert.pem")
      File.rename('pems/RL_key.orig.pem', "pems/#{user}_key.pem")

      if(PingSociety.isPingSociety)
        [[@conusDomain,'CONUS']].each do |domainandname|
          domain = domainandname[0]
          puts " Security Mop 2-4 setup domain is #{domain}" if $VerboseDebugging
          name = domainandname[1]
          auth = 'EITHER'
          puts "Domain #{domain} Name : #{name}" if $VerboseDebugging
          u = UserClass.new("P", "P", auth, 'policy', 'User', ["PolicyAdministrator"])
          puts "user created is : #{u.to_s}"
          puts "calling domain recreateUsers" if $VerboseDebugging
          domain.recreateUsers([u])
        end
      else
        [[@fwdDomain,'Fwd'], [@rearDomain,'Rear'], [@transDomain,'Trans']].each do |domainandname|
          domain = domainandname[0]
          name = domainandname[1]
          auth = 'EITHER'
          u = UserClass.new("P", "P", auth, 'policy', 'User', ["PolicyAdministrator"])
          domain.recreateUsers([u])
        end
      end
    end
  end # setup

  
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

  def perform
    ensureDomains
    puts " CALLING Perform TESTS FOR SECURITY MOP " if $VerboseDebugging
    #revokeCertBeforeTest
    #puts "sleeping for 3 minutes"
    sleep 2.minutes
    runTests(@tests)
    #runServletPolicyTests
    puts " CALLING Perform TESTS FOR SECURITY MOP  DONE "
  end


  def revokeCertBeforeTest (mycadomain,user)
    mycadomain.revokeUserCert(user)
  end

  def runRevokedCertTests
  end

  def runServletPolicyTests
    puts " CALLING Policy TESTS FOR SECURITY MOP "
    enclave = getOSDGOVAgent.enclave
    puts "Changing policy for #{enclave} to passwd "
    passwdpol = getPasswordServletPolicy
    deltaPolicy(enclave, passwdpol)
    @tests = getPasswdPolicyTests
    runTests(@tests)
    certpol = getCertServletPolicy
    deltaPolicy(enclave, certpol)
    @tests =getCertPolicyTests
     runTests(@tests)
  end  

  def ensureDomains
    puts "ensureDomains of SecurityMop 2_4 called " if $VerboseDebugging
    unless defined?(@conusDomain) and @conusDomain.kind_of?(UserDomain)
      UserDomains.instance.ensureUserDomains
      CaDomains.instance.ensureExpectedEntities
      @conusDomain = UserDomains.instance['ConusUserDomainComm']
      @fwdDomain = UserDomains.instance['1-ad-divUserDomainComm']
      @rearDomain = UserDomains.instance['RearUserDomainComm']
      @transDomain = UserDomains.instance['1-ad-divsupUserDomainComm']
      @tests = getTests
    end
  end


  def runTests(tests)
    puts "Run test called with size :#{tests.size}" if $VerboseDebugging
    tests.each do |domain, testSet|
      break if Cougaar::Actions::InitiateSecurityMopCollection.halted?
      testSet.each do |test|
        break if Cougaar::Actions::InitiateSecurityMopCollection.halted?
        type=test[0]
        agent=test[1]
        user=test[2]
        password=test[3]
        servlet=test[4]
        useCase=test[6]
        idmefPattern=test[7]
        scope=test[8]
        if scope !=nil
          scopeString =String.new(scope)        
          if (scopeString.include? "Mop2.4")
            mop24=true
          end 
          if (scopeString.include? "Mop2.6")
            mop26=true
          end
        else
          mop24=false
          mop26=false
        end
        if $VerboseDebugging
          puts "type --> #{type}"
          puts "agent --> #{agent.name}"
          puts "user --> #{user}"
          puts "password --> #{password}"
          puts "servlet --> #{servlet}"
          puts "useCase --> #{useCase}"
          puts "idmefPattern --> #{idmefPattern}"
          puts "scope --> #{scope}"
        end
        begin
          pattern = /#{agent.host.name}.*#{servlet}.*#{idmefPattern}/
          searchForLoginFailure(pattern) if scope
          # note: result is true/false
          result, expectedResult, actualResult, successBoolean, msg, body = domain.accessServletMop(test)
          if $VerboseDebugging
            puts " expectedResult -----> #{expectedResult}"
            puts " actualResult -----> #{actualResult}"
            puts " successBoolean----->#{successBoolean}"
          end
          saveAssertion(useCase,msg)
          if !successBoolean
            saveAssertion(useCase,
                          " FAILED TEST :  expectedResult:#{expectedResult} actual:#{actualResult} success:#{successBoolean} scope:#{scope}, #{expectedResult.class}, #{actualResult.class}")

          end
          if $VerboseDebugging
            puts " expectedResult:#{expectedResult} actual:#{actualResult} success:#{successBoolean} scope:#{scope}, #{expectedResult.class}, #{actualResult.class}"
          end
          if [492,493,494].member?(actualResult) # no web server or timed out 
            msg = "ignored (no web server or timed out):  #{msg}"
            # @actions << msg if scope =~ /user/
            # @policies << msg if scope =~ /policy/
            @actions << msg
            next
          end
          @numAccessAttempts += 1
          httpsRedirect = false
          httpsRedirect = true if actualResult == 491 and expectedResult == 491
          @actions << msg if !successBoolean
          if expectedResult==200
            @numLoggableActions += 1
          end
          if actualResult == 200
            @numActionsLogged += 1
            @numAccessesCorrect += 1
            @actions << "logged:  #{msg}"
            puts  "logged:  #{msg}"
          else
            waitTime=5
            if httpsRedirect
              suc = true
            else
              suc = waitForLoginFailure(waitTime)
            end
            if (mop24)   # scope =~ /user/
              if suc
                @numAccessesCorrect += 1
                @actions << "logged:  #{msg}"
                #puts  "logged:  #{msg}"
              else
                @actions << "not logged:  #{msg}"
                puts "not logged:  #{msg}"
              end
            end
            if (mop26)   # scope =~ /policy/
              @numLoggablePolicies += 1
              if suc
                @numPoliciesLogged += 1
                @policies << "logged:  #{msg}"
              else
                @policies << "not logged:  #{msg}"
              end
            end
          end # if actualResult == 200
          if $VerboseDebugging
            puts "$                 Actions logged                #{@numActionsLogged}                                                     "
            puts "$                 policy  loggable              #{@numLoggablePolicies}                                                 "
            puts "$                 policy  logged                #{@numPoliciesLogged}                                                   "
            puts "$                 Loggable Action               #{@numLoggableActions}                                                   "
            puts "$                 numAccessAttempts             #{@numAccessAttempts}                                                   "
            puts "$                 numAccessesCorrect            #{@numAccessesCorrect}                                                   "
          end
        rescue Exception => e
          puts "error in runTests"
          puts "#{e.class}: #{e.message}"
          puts e.backtrace.join("\n")
        end
      end # testSet.each
    end # tests.each
    puts "done with runTests"
    #puts "action----------------------------->   #{@actions}"
    #puts "policies----------------------------->   #{@policies}"
    #puts "logins----------------------------->   #{@logins}"
    puts "done with runTests" if $VerboseDebugging
  end # runTests
  
  def getPasswdPolicyTests
    
     begin
       puts "calling getPasswdPolicyTests "
       testCollection = {}
       testCollection[@conusDomain] =getpolicyPasswdTest
       return testCollection
     rescue Exception => e
       puts "error in SecurityMop2_4.getPasswdPolicyTests"
       puts "#{e.class}: #{e.message}"
       puts e.backtrace.join("\n")
       exit
     end
       
  end
  
   def getCertPolicyTests
     begin
       puts "calling getCertPolicyTests "
       testCollection = {}
       testCollection[@conusDomain] =getpolicyCertTest
       return testCollection
     rescue Exception => e
       puts "error in SecurityMop2_4.getCertPolicyTests"
       puts "#{e.class}: #{e.message}"
       puts e.backtrace.join("\n")
       exit
     end
       
  end


  def getTests
    begin
      fwdAgent   = run.society.agents['1-ad-divPolicyDomainManagerServlet']
      rearAgent  = run.society.agents['RearPolicyDomainManagerServlet']
      conusAgent = run.society.agents['ConusPolicyDomainManagerServlet']
      transAgent = run.society.agents['1-ad-divsupPolicyDomainManagerServlet']
      @fwdAgent   = fwdAgent
      puts "run:#{run}, #{fwdAgent}" if $VerboseDebugging
      
      if (PingSociety.isPingSociety)
        unless fwdAgent or rearAgent or conusAgent or transAgent
          raise " PolicyDomainManagerServlet agents is missing for  [Fwd|Rear|Conus|Trans]"
        end
        conusUser = "ConusPolicyUser"
        rearUser  = "RearPolicyUser"
        puts "calling test on conus user "
        testCollection = {}
        [[@conusDomain, conusAgent, conusUser, rearUser]].each do |x|
          domain = x.shift
          testCollection[domain] = self.send(:testSet, *x)
        end
        testCollection[@conusDomain] += conusTests
        return testCollection
      else
        unless fwdAgent and rearAgent and conusAgent and transAgent
          raise "One of the PolicyDomainManagerServlet agents is missing [Fwd|Rear|Conus|Trans]"
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
        return testCollection
      end 
    rescue Exception => e
      puts "error in SecurityMop2_4.getTests"
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
      exit
    end
    #return testCollection
  end # def getTests


  def testSet(agent, user, otherUser)

    if $VerboseDebugging  
      puts "agent: #{agent.name}, #{user}, #{otherUser}" if $VerboseDebugging 
      puts "Test set called with ------------->> >>   agent: #{agent.name}, #{user}, #{otherUser}"
    end
    agent = run.society.agents[agent] if agent.kind_of?(String)

    domainName = agent.userDomain.name
    policyServlet = '/policyAdmin'
    tests = [
      # auth    agent  user   password   servlet  expectedResponse
      ['Basic', agent, user,  user,      policyServlet,  200],
      ['Cert',  agent, user,  true,      policyServlet,  200],
      
      ['Basic', agent, user,  'badpasswd', policyServlet,  401, '1A1-1A20','WRONG_PASSWORD',          'Mop2.4-Mop2.6'],
      ['Cert',  agent, user,  false,     policyServlet,  403,   '1A2-1A21','INSUFFICIENT_PRIVILEGES', 'Mop2.4-Mop2.6'],
      
      ['Basic', agent, user,  user,      policyServlet,  200]
    ]
    
    if(agent == @fwdAgent)
      tests.push(
                 #['Basic', @fwdAgent, "#{domainName}\\R",  'R', policyServlet,  401, '3a','NO_PRIV','policy'])
                 ['Basic', @fwdAgent, "#{domainName}\\P",  'P', policyServlet,  401, '3a','DATABASE_ERROR','user'])
    end
    
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
      ['Cert',    osdgovAgent,    cAndPLog,    true,    servlet,    401,    '1A51-1A241',     '',                           'Mop2.4-Mop2.6']
    ]
    return tests
  end

  def getpolicyCertTest
    osdgovAgent = getOSDGOVAgent
    servlet = '/TestUserPolicy'
    cAndPLog = 'CAndPLogistician'
    tests = [
      ['Basic',    osdgovAgent,    cAndPLog,    cAndPLog,    servlet,    401,    '1A5-1A24',     '',                           'Mop2.4-Mop2.6']
    ]
    return tests
  end
  

  def conusTests
    osdgovAgent = getOSDGOVAgent
    servlet = '/TestUserPolicy'
    
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
      rearPolicyAgent = @run.society.agents['RearPolicyDomainManager']
      transPolicyAgent = @run.society.agents['TransPolicyDomainManager']
    end
    tests = [
      ['Basic',    osdgovAgent,    cAndPLog,    cAndPLog,    servlet,    200,    '1A101',     '',                           'Mop2.5'],
      ['Cert',     osdgovAgent,    cAndPLog,    true,        servlet,    200,    '1A103',     '',                           'Mop2.5'],

      #1A1 and 1A20
      ['Basic',    osdgovAgent,    cAndPLog,    badPassword, servlet,    401,    '1A1-1A20',  'WRONG_PASSWORD',             'Mop2.4-Mop2.6'],

      #1A2 and 1A21 
      ['Cert',     osdgovAgent,    cAndPLog,    false,       servlet,    403,    '1A2-1A21',  'INSUFFICIENT_PRIVILEGES',    'Mop2.4-Mop2.6'],

      #1A4 and 1A23 
      ['Cert',     osdgovAgent,    revokedLog,  true,        servlet,    403,    '1A5-1A21',  'INVALID_USER_CERTIFICATE',   'Mop2.4-Mop2.6'],
      ['Basic',    osdgovAgent,    revokedLog,  revokedLog,  servlet,    491,    '1A51-1A211','INVALID_USER_CERTIFICATE',   'Mop2.4-Mop2.6'],

      #1A6 and 1A25 
      ['Basic',    osdgovAgent,    certLog,     certLog,     servlet,    491,    '1A6-1A25',  'WRONG_PASSWORD',             'Mop2.4-Mop2.6'], 
      ['Cert',     osdgovAgent,    certLog,     true,        servlet,    200,    '1A103'],
      ['Basic',    osdgovAgent,    passwdLog,   passwdLog,   servlet,    200,    '1A101'], 
      ['Cert',     osdgovAgent,    passwdLog,   true,        servlet,    200,    '1A103'], 
      
      #1A7 and 1A26 
      ['Basic',    osdgovAgent,    deletedLog,  deletedLog,  servlet,    401,    '1A7-1A26',  'USER_DOES_NOT_EXIST',        'Mop2.4-Mop2.6'],

      #1A8 and 1A27 
      ['Cert',     osdgovAgent,    deletedLog,  true,        servlet,    403,    '1A11-1A28', 'USER_DOES_NOT_EXIST',        'Mop2.4-Mop2.6'],

      #1A9 and 1A28 
      ['Basic',    osdgovAgent,    disabledLog, disabledLog, servlet,    401,    '1A8-1A27',  'DISABLED_ACCOUNT',           'Mop2.4-Mop2.6'],

      #1A10 and 1A29 
      ['Cert',    osdgovAgent,    disabledLog, true,        servlet,     401,    '1A10-1A29', 'DISABLED_ACCOUNT',            'Mop2.4-Mop2.6'],
      ['Basic',   osdgovAgent,    notALog,     notAUser,    servlet,     401,    '1A11-1A30', 'WRONG_PASSWORD',              'Mop2.4-Mop2.6'],
      ['Cert',    osdgovAgent,    notALog,     true,        servlet,     401,    '1A12-1A30', 'INSUFFICIENT_PRIVILEGES',     'Mop2.4-Mop2.6'],
    ]   
=begin 
       #tests = [
       #  ['Basic', osdgovAgent,    cAndPLog,     cAndPLog,         servlet,          200 ,        '1A101',               ,''                              ,          'Mop2.5'         ],
       #  ['Cert',  osdgovAgent,     cAndPLog,     true,                  servlet,          200,         '1A103'                 ,''                              ,         'Mop2.5'         ],
       #  #1A1 and 1A20
       #  ['Basic', osdgovAgent,    cAndPLog,     badPassword,     servlet,          401,         '1A1/1A20',          'WRONG_PASSWORD',         'Mop2.4/Mop2.6'],
       #  #1A2 and 1A21
       #  ['Cert',  osdgovAgent,     cAndPLog,     false,                 servlet,          401,         '1A2/1A21',           'WRONG_PASSWORD',        'Mop2.4/Mop2.6'],
       #  #
       #  ['Cert',  osdgovAgent,     revokedLog,    true,         servlet,  401, '12a','REVOKED_USER','user'],
       #  ['Basic', osdgovAgent,    passwdLog,    passwdLog,        servlet,          200,         '1A101'],
       #  ['Cert',  osdgovAgent,     passwdLog,    true,                  servlet,           200,         '1A103'],
       #  ['Basic', osdgovAgent,    certLog,         certLog,             servlet,           491,         '1A5/1A24',           'WRONG_PASSWORD',       'Mop2.4/Mop2.6'],
       # ['Cert',  osdgovAgent,     certLog,         true,                  servlet,           200,          '1A103'                                                                                  ],
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
    passwdpolicy= "Policy PasswordPolicyServletAuth  = [ 
      ServletAuthenticationTemplate
  All users must use Password
  authentication when accessing the servlet named TestUserPolicyServlet
]"

    return passwdpolicy
  end

  def getCertServletPolicy
    certpolicy= "Policy CertPolicyServletAuth  = [ 
      ServletAuthenticationTemplate
  All users must use CertificateSSL
  authentication when accessing the servlet named TestUserPolicyServlet
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

