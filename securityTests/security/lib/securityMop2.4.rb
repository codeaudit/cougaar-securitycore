require 'singleton'

SnortDir = "#{ENV['CIP']}/csmart/assessment/lib/framework"
NoScore = "0.0  (see details)"
    
class AbstractSecurityMop
  attr_accessor :run, :date, :runid, :name, :descript, :score, :info, :calculationDone, :raw, :summary
  def initialize
    begin
      @run = getRun
    rescue Exception
      # do nothing
    end
    @runid = ''
    @calculationDone = false
    @summary = ''
    @info = ''
    @score = 0
    @raw = []
  end
  def setup
    # default is to do nothing
  end
  def perform
    # default is to do nothing
  end
  def shutdown
    # default is to do nothing
  end
  def calculate
    # default is to do nothing
  end
end
    
################################################

Mop2_1 = Struct.new(:agent, :type, :successes, :total)

class SecurityMop21 < AbstractSecurityMop
  attr_accessor :legitsuccesses, :legittotal
  attr_accessor :malicioussuccesses, :malicioustotal

  def initialize
    super
    @name = "2-1"
    @descript = "Percentage of sensitive data elements in computer memory that were available to an unauthorized entity"
    @detail = []
    reset
  end

  def reset
    @legitsuccesses = @legittotal = 0
    @malicioussuccesses = @malicioustotal = 0
  end

  def setup
    #Requires Oplan ready
    @nextAgent = nil
    begin
      @run.society.each_agent(true) do |agent|
        @nextAgent = agent
#        url = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/testBlackboardManager?do=start&exp=#{@run.name}"
        url = "#{agent.uri}/testBlackboardManager?do=start&exp=#{@run.name}"
        result = Cougaar::Communications::HTTP.get(url)
        #puts "result #{result}" if $VerboseDebugging
      end
    rescue Exception => e
      if @nextAgent.kind_of?(Agent)
        puts "ERROR: Could not activate testBlackboardManager on #{@nextAgent.name}"
      else
        puts "ERROR: Could not activate testBlackboardManager on #{@nextAgent.class}"
      end
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
      # raise "Could not activate testBlackboardManager"
    end
  end

  def perform
    # do nothing
  end

  def shutdown
    begin
      run.society.each_agent(true) do |agent|
        url ="http://#{agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/testBlackboardManager?do=end&exp=#{run.name}"
#        url ="#{agent.uri}/testBlackboardManager?do=end&exp=#{run.name}"
#        puts "ending testBlackboardManager #{url}" if $VerboseDebugging
        #puts url
        req=Cougaar::Communications::HTTP.get(url)
        #puts "mop 2.1 end #{agent.name}, #{url}, #{req}" if $VerboseDebugging
      end #end each agent
    rescue Exception => e
      puts "ERRR: Could not activate testBlackboardManager"
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
    end
  end

  def calculate
    begin
      sleep 1.minutes
      @score = compileResults
      puts "compiledResults #{@score}" if $VerboseDebugging
      @info = "MOP 2.1 (Blackboard access control): #{@score} - Legitimate successful tries: #{@legitsuccesses} / #{@legittotal}, malicious: #{@malicioussuccesses} / #{@malicioustotal}<br\>\n" + @info.join("<br/>\n")
      @calculationDone = true
    rescue Exception => e
puts "error, probably in compileResults" if $VerboseDebugging
      puts "error in #{self.class.name}.calculate"
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
    end
  end

  def compileResults
    mop = 0.0
    @legitsuccesses = @legittotal = @malicioussuccesses = @malicioustotal = 0
    expname=run.name
    @raw = []
    @info = []
    resultsdirectory = "#{ENV['COUGAAR_INSTALL_PATH']}/workspace/security/blackboardresults"
    files = Dir["#{resultsdirectory}/*csv"]
    files.each do |file|
      #puts "Filename:#{file}"
      lines= File.readlines(file)
      cols = lines[1].split(',')
      successes = cols[3].to_i
      failures = cols[4].to_i
      total = cols[5].to_i
      agent = cols[6]
      plugin = cols[7]

      if plugin =~ /Malicious/i
        type = "malicious"
        @malicioussuccesses += successes
        @malicioustotal += total
      else
        type = "legit"
        @legitsuccesses += successes
        @legittotal += total
      end

      @info.push("#{type} plugin on #{agent}: #{successes} successes, #{total} total")
      #@raw.push([agent, type, successes, total])
      @raw.push(Mop2_1.new(agent, type, successes, total))
    end # looping through files


    totalruns = @legittotal + @malicioustotal
    totalsuccesses = @legitsuccesses + @malicioussuccesses
    if totalruns != 0
      mop = 100 * (totalsuccesses.to_f / totalruns.to_f)
      @summary = "Legitimate: #{@legitsuccesses} correct of out #{@legittotal}. Malicious: #{@malicioussuccesses} correct out of #{@malicioustotal}.  #{mop}% correct."
    else
      mop = 100.0
      @summary = "There weren't any blackboard access attempts made, so 0% of the (non-existent) attempts were accessible to an unauthorized entity."
    end
    return mop
  end #compile results

  def scoreText
    if @summary =~ /^There weren/
      return NoScore
    else
      return @score
    end
  end
end # SecurityMop2_1

class SecurityMop2_1 < SecurityMop21
  include Singleton
end


################################################

class SecurityMop22 < AbstractSecurityMop
  def initialize
    super
    @name = "2-2"
    @descript = "Percentage of sensitive data elements stored on disk that were available to an unauthorized entity"
  end

  def calculate
    d = DataProtection.new
    @score = d.checkDataEncrypted("cougaar", 8000, false)
    @summary = d.summary
    @raw = d.filelist
    @info = d.mopHtml
    @calculationDone = true
  end

  def scoreText
    begin
      match = @summary.scan(/in ([^ ]*) persisted/)
      if match
        size = match[0][0].to_i
        if size == 0
          return NoScore
        else
          return @score
        end
      end
    rescue Exception => e
      return @score
    end
  end
end

class SecurityMop2_2 < SecurityMop22
  include Singleton
end
    
################################################

class SecurityMop23 < AbstractSecurityMop
  def initialize
    super
    @name = "2-3"
    @descript = "Percentage of sensitive data elements transmitted between computers that were available to an unauthorized entity"
  end

  def scoreText
    if @summary =~ /^There weren/
      return NoScore
    else
      return @score
    end
  end

  def startTcpCapture(agentnames)
    # executable attribute not set when first unzipped.
    %w(runsnort runsnort-aux analyzesnort analyzesnort-aux).each do |file|
      f = "#{ENV['CIP']}/csmart/assessment/lib/lib/#{file}"
      `chmod a+x #{f}`
    end
    hosts = []
    agentnames.each do |agentname|
      if agentname.kind_of?(String)
        agent = getRun.society.agents[agentname]
      else
        agent = agentname
      end
      if agent
        hosts << agent.host
      else
        logInfoMsg "Agent #{agentname} is not in the society, so no TCP capture will occur."
      end
    end
    @hosts = hosts.uniq

    puts "Starting TCP capture on hosts #{@hosts.collect {|h| h.name}.sort.inspect}" if $VerboseDebugging

    @hosts.each do |host|
      doRemoteCmd(host.name, "#{SnortDir}/runsnort #{ENV['CIP']}")
    end
  end

  def shutdown
    stopTcpCapture
  end

  def stopTcpCapture
    return unless @hosts
    logInfoMsg (@hosts.collect {|h| h.name}).sort if $VerboseDebugging
    @hosts.each do |host|
      doRemoteCmd(host.name, "#{SnortDir}/analyzesnort #{ENV['CIP']}")
    end
  end

  def calculationDone
    lognames = @hosts.collect {|host| "#{host.name}.tcplog"}
    dirfiles = Dir.entries(SecurityMopDir)
    missing = lognames - dirfiles
    puts "missing files: #{missing.inspect}" if $VerboseDebugging and missing!=[]
    return missing == []
  end

  def calculate
    @score = 100.0
    @raw = []
    @info = ''
  end
end
    
class SecurityMop2_3 < SecurityMop23
  include Singleton
end

################################################

class SecurityMop24 < AbstractSecurityMop
  attr_accessor :numAccessAttempts, :numAccessesCorrect, :logins
  attr_accessor :numActionsLogged, :numLoggableActions, :actions
  attr_accessor :numPoliciesLogged, :numLoggablePolicies, :policies

  def initialize
    super
    reset
    removePemCertificates
    @name = "2-4"
    @descript = "Percentage of user actions that were available for invocation counter to authorization policy"
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
    captureIdmefs

    # create users, change policy, etc.
    unless @fwdDomain and @runcount==run.count
      # note: NCA agent (/editOPlan) resides in conus user domain,
      #   FwdPolicyServletAgent (/policyAdmin) resides in fwd user domain.
      ensureDomains

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
      getRun.society.agents['NCA'].caDomains[0].revokeUserCert('RevokedLogistician')

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
      fwdAgent   = getRun.society.agents['1-ad-divPolicyDomainManagerServlet']
      rearAgent  = getRun.society.agents['RearPolicyDomainManagerServlet']
      conusAgent = getRun.society.agents['ConusPolicyDomainManagerServlet']
      transAgent = getRun.society.agents['1-ad-divsupPolicyDomainManagerServlet']
      @fwdAgent   = fwdAgent
puts "getRun:#{getRun}, #{fwdAgent}" if $VerboseDebugging

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
    agent = getRun.society.agents[agent] if agent.kind_of?(String)
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

class SecurityMop2_4 < SecurityMop24
  include Singleton
end

################################################

class SecurityMop25 < AbstractSecurityMop
  def initialize
    super
    @name = "2-5"
    @descript = "Percentage of all designated user actions that are recorded"
  end

  def to_s
    logged = SecurityMop2_4.instance.numActionsLogged
    total = SecurityMop2_4.instance.numLoggableActions
    answer = 100
    answer = logged / total unless total == 0
    return "policy actions: (logged)#{logged}/(total)#{total} = #{answer}"
  end

  def calculationDone
    return SecurityMop2_4.instance.calculationDone
  end

  def calculate
    while !calculationDone do
      sleep 2.seconds
    end
    @score = SecurityMop2_4.instance.score5
    logged = SecurityMop2_4.instance.numActionsLogged
    total = SecurityMop2_4.instance.numLoggableActions
    if total == 0
      if @numAccessAttempts == 0
        @summary = "There weren't any access attempts."
      else
        @summary = "There weren't any access attempts which needed to be logged."
      end
    else
      # note: these two values are swapped, but are fixed on the analysis side
      @summary = "There were #{logged} servlet access attempts, #{total} were correct."
    end
    @raw = SecurityMop2_4.instance.raw5
    @info = SecurityMop2_4.instance.html5
  end

  def scoreText
    if @summary =~ /^There weren/
      return NoScore
    else
      return @score
    end
  end
end
    
class SecurityMop2_5 < SecurityMop25
  include Singleton
end

################################################

class SecurityMop26 < AbstractSecurityMop
  def initialize
    super
    @name = "2-6"
    @descript = "Percentage of all designated user actions in violation of policy that are recorded as policy violations"
  end

  def to_s
    logged = SecurityMop2_4.instance.numPoliciesLogged
    total = SecurityMop2_4.instance.numLoggablePolicies
    answer = 100
    answer = logged / total unless total == 0
    return "policy actions: (logged)#{logged}/(total)#{total} = #{answer}"
  end

  def calculationDone
    return SecurityMop2_4.instance.calculationDone
  end

  def calculate
    while !calculationDone do
      sleep 2.seconds
    end
    @score = SecurityMop2_4.instance.score6
    logged = SecurityMop2_4.instance.numPoliciesLogged
    total = SecurityMop2_4.instance.numLoggablePolicies
    if total == 0
      if @numAccessAttempts == 0
        @summary = "There weren't any access attempts."
      else
        @summary = "There weren't any access attempts which needed to be logged."
      end
    else
      # note: these two values are swapped, but are fixed on the analysis side
      @summary = "There were #{logged} servlet access attempts, #{total} were correct."
    end
    @raw = SecurityMop2_4.instance.raw6
    @info = SecurityMop2_4.instance.html6
  end

  def scoreText
    if @summary =~ /^There weren/
      return NoScore
    else
      return @score
    end
  end
end

class SecurityMop2_6 < SecurityMop26
  include Singleton
end

##################################


def doRemoteCmd(hostname, cmd, timeout=30)
  if hostname.kind_of?(String)
    host = getRun.society.hosts[hostname]
  else
    host = hostname
  end
  cmd = "command[rexec]#{cmd}"
  logInfoMsg "doRemoteCmd: #{hostname}, #{cmd}" if $VerboseDebugging
  begin
    answer = getRun.comms.new_message(host).set_body(cmd).request(timeout)
    logInfoMsg "doRemoteCmd answer #{hostname}: #{answer.class}, #{answer}" if $VerboseDebugging
    if answer
      return getRexecBody(answer.to_s).chomp
    else
      return nil
    end
  rescue Exception => e
    backtrace = e.backtrace.join("\n")
    raise "Error in doRemoteCmd, host: #{hostname}, cmd: #{cmd}\n#{e.class}, #{e.message}\n#{backtrace}"
  end
end

def getRexecBody(xml)
  answer = xml.scan(/<body>(.*)<\/body>/m)
  return answer[0][0]
end


=begin
require 'rexml/document'
include REXML
def getRexecBody(xml)
  doc = Document.new(xml)
  type = 'error'
  doc.elements.each('message') {|ele| type = ele.attributes['type']}
  raise("Error on remote command.  Remote answer was:  [#{xml}]") if type == 'error'

  answer = ''
  doc.elements.each('message/body') do |ele|
    answer = ele.text.chomp
  end
end
=end
