
require 'security/lib/AbstractSecurityMop'
require 'security/lib/SecurityMop2_5'
require 'security/lib/rules'

class SecurityMop2_4 < AbstractSecurityMop
  attr_accessor :numAccessAttempts, :numAccessesCorrect, :logins
  attr_accessor :numActionsLogged, :numLoggableActions, :actions
  attr_accessor :numPoliciesLogged, :numLoggablePolicies, :policies

  def initialize(run)
    super(run)
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
    @score = SecurityMop2_4.instance.score4
    @raw = SecurityMop2_4.instance.raw4
    @info = SecurityMop2_4.instance.html4
    if @numAccessAttempts == 0
      @summary = "There weren't any access attempts."
    else
      @summary = "There were #{@numAccessAttempts} servlet access attempts, #{@numAccessesCorrect} were correct."
    end
    @calculationDone = true
  end

  
  def setup
    puts "Calling capture Idmefs"
    captureIdmefs
     puts "Calling capture Idmefs Done ###############################"
    # create users, change policy, etc.
    puts "Checking fwdDomain and runcount==run.count"
    unless @fwdDomain and @runcount==run.count
      # note: NCA agent (/editOPlan) resides in conus user domain,
      #   FwdPolicyServletAgent (/policyAdmin) resides in fwd user domain.
      puts "calling ensureDomains"
      ensureDomains
      puts "calling ensureDomain done"
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

      sleep 15.seconds

      @conusDomain.disableUser('DisabledLogistician')
      @conusDomain.deleteUser('DeletedLogistician')
      run.society.agents['NCA'].caDomains[0].revokeUserCert('RevokedLogistician')

      # Keep the original cert for RecreatedLogistician
      user = "ConusEnclaveCARecreatedLogistician"
      File.rename("pems/#{user}_cert.pem", 'pems/RL_cert.orig.pem')
      File.rename("pems/#{user}_key.pem", 'pems/RL_key.orig.pem')

      @conusDomain.agent.caDomains[0].revokeUserCert('RecreatedLogistician')
      @conusDomain.deleteUser('RecreatedLogistician')
      @conusDomain.recreateUsersForce(['RecreatedLogistician'])
      File.rename('pems/RL_cert.orig.pem', "pems/#{user}_cert.pem")
      File.rename('pems/RL_key.orig.pem', "pems/#{user}_key.pem")


      [[@fwdDomain,'Fwd'], [@rearDomain,'Rear'], [@transDomain,'Trans']].each do |domainandname|
        domain = domainandname[0]
        name = domainandname[1]
        auth = 'EITHER'
        u = UserClass.new("P", "P", auth, 'policy', 'User', ["PolicyAdministrator"])
        domain.recreateUsers([u])
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
    runTests(@tests)
  end

  def ensureDomains
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
        begin
          pattern = /#{agent.host.name}.*#{servlet}.*#{idmefPattern}/
          searchForLoginFailure(pattern) if scope
          # note: result is true/false
          result, expectedResult, actualResult, successBoolean, msg, body = domain.accessServletMop(test)
          #puts "failed html: #{body}" unless successBoolean
          #puts "expectedResult:#{expectedResult} actual:#{actualResult} success:#{successBoolean} scope:#{scope}, #{expectedResult.class}, #{actualResult.class}"
          if [492,493,494].member?(actualResult) # no web server or timed out
            msg = "ignored (no web server or timed out):  #{msg}"
            # @actions << msg if scope =~ /user/
            # @policies << msg if scope =~ /policy/
            @actions << msg
            next
          end
          httpsRedirect = false
          httpsRedirect = true if actualResult == 491 and expectedResult == 491
          @actions << msg if !successBoolean
          if actualResult == 200
            @numLoggableActions += 1
            @numActionsLogged += 1
            @actions << "logged:  #{msg}"
          else
            waitTime=5
            if httpsRedirect
              suc = true
            else
              suc = waitForLoginFailure(waitTime)
            end
            if true   # scope =~ /user/
              @numLoggableActions += 1
              if suc
                @numActionsLogged += 1
                @actions << "logged:  #{msg}"
              else
                @actions << "not logged:  #{msg}"
              end
            end
            if true   # scope =~ /policy/
              @numLoggablePolicies += 1
              if suc
                @numPoliciesLogged += 1
                @policies << "logged:  #{msg}"
              else
                @policies << "not logged:  #{msg}"
              end
            end
          end # if actualResult == 200
        rescue Exception => e
          puts "error in runTests"
          puts "#{e.class}: #{e.message}"
          puts e.backtrace.join("\n")
          exit
        end
      end # testSet.each
    end # tests.each
    puts "done with runTests" if $VerboseDebugging
  end # runTests

  def getTests
    
    begin
      fwdAgent   = run.society.agents['1-ad-divPolicyDomainManagerServlet']
      rearAgent  = run.society.agents['RearPolicyDomainManagerServlet']
      conusAgent = run.society.agents['ConusPolicyDomainManagerServlet']
      transAgent = run.society.agents['1-ad-divsupPolicyDomainManagerServlet']
      @fwdAgent   = fwdAgent
      puts "run:#{run}, #{fwdAgent}" if $VerboseDebugging
      
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
    rescue Exception => e
      puts "error in SecurityMop2_4.getTests"
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
      exit
    end
  end # def getTests


  def testSet(agent, user, otherUser)
    puts "agent: #{agent.name}, #{user}, #{otherUser}" if $VerboseDebugging
    agent = run.society.agents[agent] if agent.kind_of?(String)
    domainName = agent.userDomain.name
    policyServlet = '/policyAdmin'
    tests = [
      # auth    agent  user   password   servlet  expectedResponse
      ['Basic', agent, user,  user,      policyServlet,  200],
      ['Cert',  agent, user,  true,      policyServlet,  200],
      
      ['Basic', agent, user,  'badpasswd', policyServlet,  401, '1a','WRONG_PASSWORD','user'],
      ['Cert',  agent, user,  false,     policyServlet,  401, '2a','WRONG_PASSWORD','user'],
      
      ['Basic', agent, user,  user,      policyServlet,  200]
    ]
    
    unless agent == @fwdAgent
      tests.push(
                 #['Basic', @fwdAgent, "#{domainName}\\R",  'R', policyServlet,  401, '3a','NO_PRIV','policy'])
                 ['Basic', @fwdAgent, "#{domainName}\\P",  'P', policyServlet,  401, '3a','DATABASE_ERROR','user'])
    end
    
    return tests
  end # testSet
  
  def conusTests
    ncaAgent = @run.society.agents["NCA"]
    editOPlan = '/editOplan'
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

    policyAgent = @run.society.agents['FwdPolicyDomainManager']
    policyServlet = '/policyAdmin'
    fwdAdmin = 'FwdPolicyAdmin'
    remoteFwdAdmin = 'ConusUserDomainComm\\R'
    fwdAdminFromConus2 = 'ConusUserDomainComm\FwdPolicyAdminFromConus'
    conusAdmin = 'ConusPolicyAdmin'

    rearPolicyAgent = @run.society.agents['RearPolicyDomainManager']
    transPolicyAgent = @run.society.agents['TransPolicyDomainManager']
    
    tests = [
      ['Basic', ncaAgent, cAndPLog,     cAndPLog,     editOPlan,  200],
      ['Cert',  ncaAgent, cAndPLog,     true,         editOPlan,  200],
      ['Basic', ncaAgent, cAndPLog,     badPassword,  editOPlan,  401, '5a','WRONG_PASSWORD','user'],
      ['Cert',  ncaAgent, cAndPLog,     false,        editOPlan,  401, '6a','WRONG_PASSWORD','user'],
      ['Basic', ncaAgent, passwdLog,    passwdLog,    editOPlan,  200],
      ['Cert',  ncaAgent, passwdLog,    true,         editOPlan,  200],
      ['Basic', ncaAgent, certLog,      certLog,      editOPlan,  491, '7a','WRONG_PASSWORD','policy'],
      ['Cert',  ncaAgent, certLog,      true,         editOPlan,  200],
      
      ['Basic', ncaAgent, notALog,      notAUser,     editOPlan,  401, '10a','WRONG_PASSWORD','user'],
      ['Basic', ncaAgent, disabledLog,  disabledLog,  editOPlan,  401, '11a','DISABLED_ACCOUNT','user'],
      ['Cert',  ncaAgent, disabledLog,  true,         editOPlan,  401, '11c','DISABLED_ACCOUNT','user'],
      ['Basic', ncaAgent, deletedLog,   deletedLog,   editOPlan,  401, '11e','USER_DOES_NOT_EXIST','user'],
      ['Cert',  ncaAgent, deletedLog,   true,         editOPlan,  401, '11g','USER_DOES_NOT_EXIST','user'],
      ['Cert',  ncaAgent, revokedLog,   true,         editOPlan,  401, '12a','REVOKED_USER','user'],
      # try to use a previously created cert
      ['Cert',  ncaAgent, recreatedLog, true,         editOPlan,  401, '13a','WRONG_PASSWORD','puser']
      ###['Cert',  ncaAgent, otherCert,    true,         editOPlan,  401, '14a','WRONG_PASSWORD','user']
    ]
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

end # class SecurityMop2_4
