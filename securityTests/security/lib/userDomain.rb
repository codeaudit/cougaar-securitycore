##
#  <copyright>
#  Copyright 2003 SRI International
#  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the Cougaar Open Source License as published by
#  DARPA on the Cougaar Open Source Website (www.cougaar.org).
#
#  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
#  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
#  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
#  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
#  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
#  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
#  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#  PERFORMANCE OF THE COUGAAR SOFTWARE.
# </copyright>
#

# This section adds 'userAdminAgent' and 'caSignerAgent' methods to nodes
# and agents. These allow for finding agent responsible for this managing
# this agent's user domain and certificate signing.

require 'cougaar/communities'
require 'ultralog/enclaves'
require 'singleton'
require 'security/lib/userDomainAux'
require 'security/lib/experimentFramework'




module Cougaar

  module Actions
    class SetUserAdminAgents < Cougaar::Action
      def perform
        setUserAdminAgents
      end
    end
  end


  module Model


    class Agent
      attr_accessor :userDomain
      def userDomain
        if @userDomain
          return @userDomain
        else
          return node.userDomain
        end
      end
    end

    class Node
      attr_accessor :userDomain
    end


  end  # Model
end # Cougaar


#-------------------------------------------------

class UserDomain
  def ensureDomains
    UserDomains.instance.ensureDomains
  end

  def to_s
    agentName = ''
    agentName = @agent.name if @agent
    "  UserDomain name=#{@name}\n  agent=#{@agentName}\n  domainAgents=#{@domainAgents.collect {|agent| agent.name}.as_string}\n"
  end

  #----------  Access Attempt Methods -----------

  def getThreatLevel(agent)
    answer = 'LOW'
    url = "#{agent.uri}/ae?frame=ae"
    #puts "url:#{url}  agent:#{agent}   class:#{agent.class}"
    result = getHtml(url)
    if result
      #puts result.body
      level = result.body.scan(/THREATCON_LEVEL = (.*)/)
      if level and level != []
        puts "threatcon level:#{level.inspect}" if $VerboseDebugging
        answer = level[0][0]
      end
    end
    return answer
  end

  # Attempts accessing a servlet
  def accessServletAux(test)
    web = SRIWeb.new
    #      basicAuthPort = run.society.cougaar_port
    #puts "basicAuthPort: #{basicAuthPort}"
    timeout = 90
    if test[0].kind_of? Integer then
      count = test[0]
      test = test[1..-1]
    else
      count = 1
    end
    authentication = test[0]
    agent = test[1]
    user = test[2]
    password = test[3]
    servlet = test[4]
    expectedResult = Integer(test[5])
    useCase = test[6]
    
    # moved this down.
    #if authentication=="Basic" and getThreatLevel(agent)=='HIGH'
    #  expectedResult = 491
    #end

    result = true

    puts "Trying with #{user}, #{password} to servlet #{servlet}" if $VerboseDebugging
    caDomainSet = agent.caDomains[0]
    caDomainName = caDomainSet.name
    keyfile = "#{caDomainName}#{user}_key.pem"
    certfile = "#{caDomainName}#{user}_cert.pem"
    boguscertfile = "#{caDomainName}BogusUser_cert.pem"
    boguskeyfile = "#{caDomainName}BogusUser_key.pem"
    body = ''
    if authentication == 'Basic'
      url = "#{agent.uri}#{servlet}"
      puts ['basic_auth',url,user,password].as_string if $VerboseDebugging
      #puts ['basic_auth',url,user,password].as_string
      web.set_auth(user, password)
      result = web.getHtml(url, 1.minute, 3, false)
      body = result.body
      #puts "result.body = #{result.body}"  if result.code!="200"
      result = result.code
    elsif password == true then
      #   servlet = "/\$"+agent.name+servlet
      servlet = agent.secure_uri+servlet
      puts "password ==>true  keyfile ===>#{keyfile}  certfile ==>#{certfile} 401 retry ==>false" if $VerboseDebugging
      result = getHtmlSsl(servlet, keyfile, certfile, 60.seconds, 3, false)
      body = result.body
      result = result.status
    else
      servlet = agent.secure_uri+servlet
      puts "password ==>false  keyfile ===>#{boguskeyfile}  certfile ==>#{boguscertfile} 401 retry ==>false" if $VerboseDebugging
      result = getHtmlSsl(servlet, boguskeyfile, boguscertfile, 60.seconds, 3, false)
      body = result.body
      result = result.status
    end

    code = 0
    begin
      code = Integer(result)
    rescue Exception
      code = 0
    end
    # Code 405 indicates authentication is okay, but GET is not supported, only POST
    code = 200 if code == 405

    if $VerboseDebugging
      #  puts
      puts "code:#{code}  expectedResult:#{expectedResult}"
      puts
    end

    if (expectedResult==200 and code==491 and authentication=='Basic')
      if authentication=="Basic" and getThreatLevel(agent)=='HIGH'
        expectedResult = 491
      end
    end

    successBoolean = false
    if [492,493,494].member?(code)
      msg = "ignored: Web server not up with #{user}, #{password} to servlet #{servlet} (retcode=#{code})"
      return successBoolean, code, expectedResult, useCase, msg, body
    end

    if (expectedResult==200 and code==200) or (expectedResult!=200 and code!=200) then
      success = 'Success'
      successBoolean = true
    else
      success = 'Failed'
      successBoolean = false
      result = false
    end
    if code == 200 then
      allowed = 'allowed'
    else
      allowed = 'denied'
    end
    if authentication=="Basic"
      msg = "#{success}: Authentication #{allowed} with #{user}, #{password} to servlet #{servlet} (RETCODE=#{code})"
    else 
      if password == false
        msg = "#{success}: Authentication #{allowed} with invalid Certificate for user #{user} to servlet #{servlet} (RETCODE=#{code})"
      else
         msg = "#{success}: Authentication #{allowed} with valid Certificate for user #{user}  to servlet #{servlet} (RETCODE=#{code})"
      end
    end
    return successBoolean, code, expectedResult, useCase, msg, body

  end

  def accessServlet(test)
    count = 1
    count = test[0] if test[0].kind_of?(Integer)

    result = true
    count.times do |counter|
      successBoolean, actualResult, expectedResult, useCase, msg, body = accessServletAux(test)
      result = false unless successBoolean
      if useCase
        saveResult(successBoolean, useCase, msg)
      else
        saveAssertion "", msg
      end
      #      addUserTry Time.now, msg, code
      sleep(1.seconds) unless counter>=count
    end
    return result
  end

  def accessServletMop(test)
    count = 1
    if test[0].kind_of?(Integer)
      puts "WARNING:  security mop 2.4 tests shouldn't have a repeat value in (userDomain)accessServletMop"
      count = test[0]
      test = test[1..-1]
    end

    result = true
    actualResult = -1
    mop = SecurityMop2_4.instance
    msg = ''
    successBoolean = false
    body = ''
    expectedResult = 0
    count.times do |counter|
      successBoolean, actualResult, expectedResult, useCase, msg, body = accessServletAux(test)
      #mop.logins << msg
      next if [492,493,494].member?(actualResult)
      result = false unless successBoolean
      #mop.numAccessAttempts += 1
      #if successBoolean
      #  mop.numAccessesCorrect += 1 if successBoolean
      #else
      #  ###        mop.numAccessesCorrect += 1 if !successBoolean
      #end
      #puts [successBoolean, useCase, msg]
      #      addUserTry Time.now, msg, code
      sleep(1.seconds) unless counter>=count
    end
    return result, expectedResult, actualResult, successBoolean, msg, body
  end
  
  def getOSDGOVAgent
    run.society.each_agent(true) { |agent|
      agent.each_facet("org_id") { |facet| 
        if facet["org_id"] == "OSD.GOV"
          return agent
        end
      }
    }
  end
  
  def do_cert_auth(userName, hostName, urlPath)
    return nil if ( userName == nil || hostName == nil || urlPath == nil)
    begin
      certFile = "#{userName}_cert.pem"
      keyFile = "#{userName}_key.pem"
      # portNumber = getRun.society.agents['NCA'].node.secure_cougaar_port
      portNumber = getOSDGOVAgent.node.secure_cougaar_port
      #puts "secureport=#{portNumber}"
      logInfoMsg "Doing Certificate Authentication for #{urlPath} with user=#{userName} on host #{hostName}:#{portNumber}"
      #      logInfoMsg "python ./do_cert_auth.py '#{hostName}' '#{portNumber}' '#{certFile}' '#{keyFile}' '#{urlPath}'"
      #      resp = %x{python ./do_cert_auth.py '#{hostName}' '#{portNumber}' '#{certFile}' '#{keyFile}' '#{urlPath}'}
      url = "https://#{hostName}:#{portNumber}#{urlPath}"
      #   puts url
      resp = getHtmlSsl(url, keyFile, certFile)
      logInfoMsg "RETCODE=|#{resp}| :Login to #{urlPath} using user=#{userName} and GoodCertificate"
      return resp
    rescue Exception => e
      logInfoMsg "Cougaar::AssessmentOperations exception"
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
    end
  end

  def do_bogus_cert_auth(userName, hostName, urlPath)
    return nil if ( userName == nil || hostName == nil || urlPath == nil )
    return do_cert_auth("bogus_"+userName, hostName, urlPath)
  end

end # class UserDomain


#---------------------------------------------------------

class UserDomains
  include Singleton
  include Enumerable

  attr_accessor :domains

  def ensureDomains
    @domains = {} unless @domains
  end

  def [](domainName)
    ensureDomains
    unless @domains[domainName]
      @domains[domainName] = UserDomain.new(domainName)
    end
    return @domains[domainName]
  end

  def domains
    ensureDomains
    return @domains
  end

  def each(&block)
    ensureDomains
    domains.each do |domainName, userDomain|
      yield domainName, userDomain
    end
  end

  def printIt
    puts 'in userDomain.printIt'
    each do |domainName, userDomain|
      puts userDomain
      puts
    end
    puts '   done userDomain.printIt'
  end

  def ensureUserDomains
    # this only needs to be performed once.
    #puts " ensureUserDomains called from UserDomain"
    return nil if @userAdminHasBeenSet
    #puts " ensureUserDomains userAdminHasBeenSet "
    @userAdminHasBeenSet = true
    getUserCommunities.each do |community|
      #puts " ensureUserDomains looping through each community "
      userDomain = self[community.name]
      #puts " ensureUserDomains----------> #{userDomain}"
      members = []
      userAdmins = []
      # this walks through the agents/nodes of this community
      community.each do |entity|
        agent = run.society.entity(entity.name)
       	 puts "member agent: #{agent}, #{entity.name}"
        members << agent
        # check if this is the userAdmin agent for this community
        entity.each_role do |role|
          if role == 'UserManager'
            userAdmins << agent
          end
        end
      end
      if userAdmins.size == 1
        makeDomainAssociations userDomain, userAdmins, members
      elsif userAdmins.size > 0
        logWarningMsg "more than one UserManager in community #{community.name}; will use the first one."
        makeDomainAssociations userDomain, userAdmins, members
      else
        logErrorMsg "no UserManager in community #{community.name}"
        exit
      end
      #puts "userdomain #{userDomain}, #{userDomain.class}"
    end
  end
  
  def makeDomainAssociations(userDomain, userAdmins, members)
    userDomain.agent = userAdmins[0]
    #puts 'hi'
    #puts members.size
    #puts members
    userDomain.domainAgents = members
    members.each {|e| e.userDomain = userDomain}  #userAdmins[0]}
  end

  def getUserCommunities
    communities = []
    run.society.communities.each do |community|
      community.each_attribute do |key, value|
        if key=='CommunityType' and value=='User'
          communities << community
        end
      end
    end
    return communities
  end

end # class UserDomains

#end # module Model
#end # module Cougaar




# The following code creates hashes based on time for UserTry and Idmef
def addUserTry(time, usertry, returnStatusCode)
  ensureUserTry
  @userTries[time] = [usertry, returnStatusCode]
end
def removeUserTry(time)
  ensureUserTry
  @userTries.delete(time)
end
def ensureUserTry
  if not defined? @userTries
    @userTries = {}
  end
end

def addIdmef(time, event)
  ensureIdmef
  @idmefs[time] = event
end
def removeIdmef(time)
  ensureIdmef
  @idmefs.delete(time)
end
def forEachIdmef(&block)
  ensureIdmef
  @idmefs.each do |key, value|
    yield key, value
  end
end
def ensureIdmef
  if not defined? @idmefs
    @idmefs = {}
  end
end
